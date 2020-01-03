/*
 *
 * Copyright 2019 The KubeSphere Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"text/template"
)

type Config struct {
	Name        string
	Description string
	Icon        string
	oauth2.Config
	IdentifyProvider    IdentifyProvider
	tokenExchangePlugin TokenExchangePlugin
	userInfoPlugin      UserInfoPlugin
}

type PublicConfig struct {
	*Config
	IdentifyProvider *IdentifyProvider `json:"IdentifyProvider,omitempty"`
	ClientSecret     *string           `json:"ClientSecret,omitempty"`
}

var configs []*Config
var publicConfigs = make([]PublicConfig, 0)

const (
	configFile = "/etc/kubesphere/oauth/configs.json"
)

func init() {
	data, err := ioutil.ReadFile(configFile)
	if err == nil {
		var c []*Config

		err := json.Unmarshal(data, &c)

		if err != nil {
			fmt.Printf("oauth2 config load failed:%v\n", err)
		}

		for _, config := range c {
			if LoadConfig(config.Name) == nil {
				if err := config.validate(); err != nil {
					fmt.Printf("oauth2 config load failed:%v\n", err)
					continue
				}
				configs = append(configs, config)
				publicConfigs = append(publicConfigs, PublicConfig{Config: config})
			}
		}
	}
}

func LoadConfig(name string) *Config {
	for _, config := range configs {
		if config.Name == name {
			return config
		}
	}
	return nil
}

func PublicConfigs() []PublicConfig {
	return publicConfigs
}

func (c *Config) validate() error {
	if c.IdentifyProvider.UsernameAttribute == "" || c.IdentifyProvider.EmailAttribute == "" {
		return fmt.Errorf("IdentifyProvider.UsernameAttribute and IdentifyProvider.EmailAttribute must be specified")
	}

	usernameTmpl, err := template.New("username").Parse(c.IdentifyProvider.UsernameAttribute)

	if err != nil {
		return fmt.Errorf("IdentifyProvider.UsernameAttribute is invalid:%v", err)
	}

	c.IdentifyProvider.usernameTmpl = usernameTmpl

	emailTmpl, err := template.New("email").Parse(c.IdentifyProvider.EmailAttribute)

	if err != nil {
		return fmt.Errorf("IdentifyProvider.EmailAttribute is invalid:%v", err)
	}

	c.IdentifyProvider.emailTmpl = emailTmpl

	return nil
}

func (c *Config) SetTokenExchangePlugin(plugin TokenExchangePlugin) {
	c.tokenExchangePlugin = plugin
}

func (c *Config) SetUserInfoPlugin(plugin UserInfoPlugin) {
	c.userInfoPlugin = plugin
}

func (c *Config) TokenExchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if c.tokenExchangePlugin != nil {
		return c.tokenExchangePlugin.TokenExchange(context.Background(), code)
	} else {
		return c.Config.Exchange(context.Background(), code)
	}
}

func (c *Config) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {
	if c.userInfoPlugin != nil {
		return c.userInfoPlugin.GetUserInfo(token)
	} else {
		return c.IdentifyProvider.GetUserInfo(token)
	}
}
