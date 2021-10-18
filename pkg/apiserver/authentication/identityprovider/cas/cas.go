/*
Copyright 2020 The KubeSphere Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cas

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/mitchellh/mapstructure"
	gocas "gopkg.in/cas.v2"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
)

func init() {
	identityprovider.RegisterOAuthProvider(&casProviderFactory{})
}

type cas struct {
	RedirectURL        string `json:"redirectURL" yaml:"redirectURL"`
	CASServerURL       string `json:"casServerURL" yaml:"casServerURL"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`
	client             *gocas.RestClient
}

type casProviderFactory struct {
}

type casIdentity struct {
	User string `json:"user"`
	ID   string `json:"id"`
}

func (c casIdentity) GetUserID() string {
	return c.User
}

func (c casIdentity) GetUsername() string {
	return c.User
}

func (c casIdentity) GetEmail() string {
	return ""
}

func (f casProviderFactory) Type() string {
	return "CASIdentityProvider"
}

func (f casProviderFactory) Create(options oauth.DynamicOptions) (identityprovider.OAuthProvider, error) {
	var cas cas
	if err := mapstructure.Decode(options, &cas); err != nil {
		return nil, err
	}
	casURL, err := url.Parse(cas.CASServerURL)
	if err != nil {
		return nil, err
	}
	redirectURL, err := url.Parse(cas.RedirectURL)
	if err != nil {
		return nil, err
	}
	cas.client = gocas.NewRestClient(&gocas.RestOptions{
		CasURL:     casURL,
		ServiceURL: redirectURL,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cas.InsecureSkipVerify},
			},
		},
		URLScheme: nil,
	})
	return &cas, nil
}

func (c cas) IdentityExchange(ticket string) (identityprovider.Identity, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify},
	}
	client := &http.Client{Transport: tr}
	serviceValidateURL := fmt.Sprintf("%s/serviceValidate?&service=%s&ticket=%s", c.CASServerURL, c.RedirectURL, ticket)
	resp, err := client.Get(serviceValidateURL)
	if err != nil {
		return nil, fmt.Errorf("cas validate service failed: %v", err)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cas read data failed: %v", err)
	}

	casResponse, err := gocas.ParseServiceResponse(data)
	if err != nil {
		return nil, fmt.Errorf("cas authentication failed: %v", err)
	}

	if len(casResponse.Attributes["userDetail"]) == 0 {
		return nil, fmt.Errorf("cas authentication failed: %v", "missing required field \"userDetail\"")
	}

	var userDetail userDetail
	if err = json.Unmarshal([]byte(casResponse.Attributes["userDetail"][0]), &userDetail); err != nil {
		return nil, fmt.Errorf("cas authentication failed: %v", err)
	}

	return &casIdentity{ID: userDetail.Mobile, User: casResponse.User}, nil
}

type userDetail struct {
	Mobile string `json:"mobile"`
}
