/*
 *
 * Copyright 2020 The KubeSphere Authors.
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

package plugin_sample

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	ksoauth2 "kubesphere.io/kubesphere/pkg/models/oauth"
	"net/http"
)

func Setup(config *ksoauth2.Config) error {
	plugin := &Plugin{config: config}
	config.SetTokenExchangePlugin(plugin)
	config.SetUserInfoPlugin(plugin)
	return nil
}

type Plugin struct {
	config *ksoauth2.Config
}

func (p *Plugin) TokenExchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	resp, err := http.Post(fmt.Sprintf("%s?client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s", p.config.Endpoint.TokenURL, p.config.ClientID, p.config.ClientSecret, code), "", nil)

	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	err = json.Unmarshal(data, &token)

	if err != nil {
		return nil, fmt.Errorf("oauth2: server response missing access_token")
	}

	return &token, nil
}

func (p *Plugin) GetUserInfo(token *oauth2.Token) (*ksoauth2.UserInfo, error) {
	url := fmt.Sprintf("%s?access_token=%s", p.config.IdentifyProvider.URL, token.AccessToken)
	resp, err := http.Get(url)

	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return nil, err
	}

	return p.config.IdentifyProvider.Parse(data)
}
