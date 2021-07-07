/*

 Copyright 2021 The KubeSphere Authors.

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

package dispatch

import (
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/proxy"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/klog"
	"kubesphere.io/kubesphere/pkg/apiserver/request"
	component "kubesphere.io/kubesphere/pkg/client/informers/externalversions/component/v1alpha1"
	"kubesphere.io/kubesphere/pkg/utils/sliceutil"
	"net/http"
	"net/url"
)

type apiServiceDispatch struct {
	apiServiceInformer component.APIServiceInformer
}

func (s *apiServiceDispatch) Dispatch(w http.ResponseWriter, req *http.Request, handler http.Handler) bool {
	info, _ := request.RequestInfoFrom(req.Context())
	apiServices, err := s.apiServiceInformer.Lister().List(labels.Everything())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	for _, apiService := range apiServices {
		if apiService.Status.Enabled && (sliceutil.HasString(apiService.Spec.NonResourceURLs, info.Path) ||
			(apiService.Spec.Group == info.APIGroup && apiService.Spec.Version == info.APIVersion)) {
			endpoint, err := url.Parse(apiService.Spec.Endpoint)
			if err != nil {
				responsewriters.InternalError(w, req, err)
				return true
			}
			u := req.URL
			u.Host = endpoint.Host
			u.Scheme = endpoint.Scheme
			httpProxy := proxy.NewUpgradeAwareHandler(req.URL, http.DefaultTransport, false, false, s)
			httpProxy.ServeHTTP(w, req)
			return true
		}
	}
	return false
}

func (s *apiServiceDispatch) Error(w http.ResponseWriter, req *http.Request, err error) {
	klog.Error(err)
}

func NewAPIServiceDispatch(apiServiceInformer component.APIServiceInformer) Dispatcher {
	return &apiServiceDispatch{apiServiceInformer: apiServiceInformer}
}
