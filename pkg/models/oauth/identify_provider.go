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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/oauth2"
	"io/ioutil"
	"text/template"
)

type UserInfo struct {
	Username string
	Email    string
}

type IdentifyProvider struct {
	URL               string
	UsernameAttribute string
	EmailAttribute    string
	usernameTmpl      *template.Template
	emailTmpl         *template.Template
}

func (p *IdentifyProvider) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {
	r, err := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token)).Get(p.URL)

	if err != nil {
		glog.Error(err)
		return nil, err
	}

	data, err := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if err != nil {
		glog.Error(err)
		return nil, err
	}

	return p.Parse(data)
}

func (p *IdentifyProvider) Parse(data []byte) (*UserInfo, error) {
	var m map[string]interface{}

	err := json.Unmarshal(data, &m)

	if err != nil {
		glog.Error(err)
		return nil, err
	}
	var username bytes.Buffer
	err = p.usernameTmpl.Execute(&username, m)
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	var email bytes.Buffer
	err = p.emailTmpl.Execute(&email, m)
	if err != nil {
		glog.Error(err)
		return nil, err
	}

	if username.String() != "<no value>" && email.String() != "<no value>" {
		return &UserInfo{
			Username: username.String(),
			Email:    email.String(),
		}, nil
	}
	return nil, fmt.Errorf("cannot obtain user info:%s", string(data))
}
