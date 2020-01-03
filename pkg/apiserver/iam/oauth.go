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

package iam

import (
	"fmt"
	"github.com/emicklei/go-restful"
	"kubesphere.io/kubesphere/pkg/models/iam"
	ksoauth "kubesphere.io/kubesphere/pkg/models/oauth"
	"kubesphere.io/kubesphere/pkg/server/errors"
	"kubesphere.io/kubesphere/pkg/utils/iputil"
	"net/http"
)

type OAuthLoginRequest struct {
	Code string `json:"code"`
}

func OAuthConfigs(req *restful.Request, resp *restful.Response) {
	resp.WriteEntity(ksoauth.PublicConfigs())
}

func OAuthLogin(req *restful.Request, resp *restful.Response) {

	configName := req.PathParameter("name")

	var loginRequest OAuthLoginRequest

	err := req.ReadEntity(&loginRequest)

	if err != nil || loginRequest.Code == "" {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(fmt.Errorf("code must be specified")))
		return
	}

	config := ksoauth.LoadConfig(configName)

	if config == nil {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(fmt.Errorf("oauth plugin %s is not enabled", configName)))
		return
	}

	ip := iputil.RemoteIp(req.Request)
	result, err := iam.OAuthLogin(config, loginRequest.Code, ip)

	if err != nil {
		resp.Header().Set("WWW-Authenticate", err.Error())
		resp.WriteHeaderAndEntity(http.StatusUnauthorized, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}
