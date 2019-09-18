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
package v1

import (
	"github.com/emicklei/go-restful"
	"github.com/emicklei/go-restful-openapi"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"kubesphere.io/kubesphere/pkg/apiserver/openpitrix"
	"kubesphere.io/kubesphere/pkg/apiserver/runtime"
	"kubesphere.io/kubesphere/pkg/constants"
	"kubesphere.io/kubesphere/pkg/models"
	opmodels2 "kubesphere.io/kubesphere/pkg/models/openpitrix"
	"kubesphere.io/kubesphere/pkg/server/errors"
	"kubesphere.io/kubesphere/pkg/server/params"
	"net/http"
	opmodels "openpitrix.io/openpitrix/test/models"
)

const GroupName = "openpitrix.io"

var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1"}

var (
	WebServiceBuilder = runtime.NewContainerBuilder(addWebService)
	AddToContainer    = WebServiceBuilder.AddToContainer
)

func addWebService(c *restful.Container) error {

	ok := "ok"
	mimePatch := []string{runtime.MimeMergePatchJson, runtime.MimeJsonPatchJson}
	webservice := runtime.NewWebService(GroupVersion)

	webservice.Route(webservice.GET("/namespaces/{namespace}/applications").
		To(openpitrix.ListNamespacedApplication).
		Returns(http.StatusOK, ok, models.PageableResponse{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.NamespaceResourcesTag}).
		Doc("List all applications within the specified namespace").
		Param(webservice.QueryParameter(params.ConditionsParam, "query conditions, connect multiple conditions with commas, equal symbol for exact query, wave symbol for fuzzy query e.g. name~a").
			Required(false).
			DataFormat("key=value,key~value").
			DefaultValue("")).
		Param(webservice.PathParameter("namespace", "the name of the project")).
		Param(webservice.QueryParameter(params.PagingParam, "paging query, e.g. limit=100,page=1").
			Required(false).
			DataFormat("limit=%d,page=%d").
			DefaultValue("limit=10,page=1")))

	webservice.Route(webservice.GET("/namespaces/{namespace}/applications/{application}").
		To(openpitrix.DescribeApplication).
		Returns(http.StatusOK, ok, opmodels2.Application{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.NamespaceResourcesTag}).
		Doc("Describe the specified application of the namespace").
		Param(webservice.PathParameter("namespace", "the name of the project")).
		Param(webservice.PathParameter("application", "application ID")))

	webservice.Route(webservice.POST("/namespaces/{namespace}/applications").
		To(openpitrix.CreateApplication).
		Doc("Deploy a new application").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.NamespaceResourcesTag}).
		Reads(opmodels.OpenpitrixCreateClusterRequest{}).
		Returns(http.StatusOK, ok, errors.Error{}).
		Param(webservice.PathParameter("namespace", "the name of the project")))

	webservice.Route(webservice.DELETE("/namespaces/{namespace}/applications/{application}").
		To(openpitrix.DeleteApplication).
		Doc("Delete the specified application").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.NamespaceResourcesTag}).
		Returns(http.StatusOK, ok, errors.Error{}).
		Param(webservice.PathParameter("namespace", "the name of the project")).
		Param(webservice.PathParameter("application", "application ID")))

	webservice.Route(webservice.POST("/apps/{app}/versions").
		To(openpitrix.CreateAppVersion).
		Doc(""))
	webservice.Route(webservice.DELETE("/apps/{app}/versions/{version}").
		To(openpitrix.DeleteAppVersion).
		Doc(""))
	webservice.Route(webservice.PATCH("/apps/{app}/versions/{version}").
		Consumes(mimePatch...).
		To(openpitrix.PatchAppVersion).
		Doc(""))
	webservice.Route(webservice.GET("/apps/{app}/versions/{version}").
		To(openpitrix.DescribeAppVersion).
		Doc(""))
	webservice.Route(webservice.GET("/apps/{app}/versions").
		To(openpitrix.ListAppVersions).
		Doc("Get active versions of app, can filter with these fields(version_id, app_id, name, owner, description, package_name, status, type), default return all active app versions").
		Param(webservice.QueryParameter(params.ConditionsParam, "query conditions,connect multiple conditions with commas, equal symbol for exact query, wave symbol for fuzzy query e.g. name~a").
			Required(false).
			DataFormat("key=%s,key~%s")).
		Param(webservice.QueryParameter(params.PagingParam, "paging query, e.g. limit=100,page=1").
			Required(false).
			DataFormat("limit=%d,page=%d").
			DefaultValue("limit=10,page=1")).
		Param(webservice.PathParameter("app", "app template id")).
		Param(webservice.QueryParameter(params.ReverseParam, "sort parameters, e.g. reverse=true")).
		Param(webservice.QueryParameter(params.OrderByParam, "sort parameters, e.g. orderBy=createTime")).
		Returns(http.StatusOK, ok, &models.PageableResponse{}))
	webservice.Route(webservice.GET("/apps/{app}/versions/{version}/audits").
		To(openpitrix.ListAppVersionAudits).
		Doc(""))
	webservice.Route(webservice.GET("/apps/{app}/versions/{version}/package").
		To(openpitrix.GetAppVersionPackage).
		Doc(""))
	webservice.Route(webservice.POST("/apps/{app}/versions/{version}/action").
		To(openpitrix.DoAppVersionAction).
		Doc(""))
	webservice.Route(webservice.GET("/apps/{app}/versions/{version}/files").
		To(openpitrix.GetAppVersionFiles).
		Doc(""))
	webservice.Route(webservice.GET("/reviews").
		To(openpitrix.ListReviews).
		Doc(""))
	webservice.Route(webservice.GET("/apps/{app}/audits").
		To(openpitrix.ListAppVersionAudits).
		Doc(""))

	webservice.Route(webservice.POST("/apps").
		To(openpitrix.CreateApp).
		Doc(""))
	webservice.Route(webservice.DELETE("/apps/{app}").
		To(openpitrix.DeleteApp).
		Doc(""))
	webservice.Route(webservice.PATCH("/apps/{app}").
		Consumes(mimePatch...).
		To(openpitrix.PatchApp).
		Doc(""))
	webservice.Route(webservice.GET("/apps/{app}").
		To(openpitrix.DescribeApp).
		Doc(""))
	webservice.Route(webservice.GET("/apps").
		To(openpitrix.ListApps).
		Doc("Get active apps, can filter with these fields(app_id, name, repo_id, description, status, home, icon, screenshots, maintainers, sources, readme, owner, chart_name), default return all apps").
		Param(webservice.QueryParameter(params.ConditionsParam, "query conditions,connect multiple conditions with commas, equal symbol for exact query, wave symbol for fuzzy query e.g. name~a").
			Required(false).
			DataFormat("key=%s,key~%s")).
		Param(webservice.QueryParameter(params.PagingParam, "paging query, e.g. limit=100,page=1").
			Required(false).
			DataFormat("limit=%d,page=%d").
			DefaultValue("limit=10,page=1")).
		Param(webservice.QueryParameter(params.ReverseParam, "sort parameters, e.g. reverse=true")).
		Param(webservice.QueryParameter(params.OrderByParam, "sort parameters, e.g. orderBy=createTime")).
		Returns(http.StatusOK, ok, &models.PageableResponse{}))
	webservice.Route(webservice.POST("/validate/package").
		To(openpitrix.ValidatePackage).
		Doc(""))

	webservice.Route(webservice.POST("/categories").
		To(openpitrix.CreateCategory).
		Doc(""))
	webservice.Route(webservice.DELETE("/categories/{category}").
		To(openpitrix.DeleteCategory).
		Doc(""))
	webservice.Route(webservice.PATCH("/categories/{category}").
		Consumes(mimePatch...).
		To(openpitrix.PatchCategory).
		Doc(""))
	webservice.Route(webservice.GET("/categories/{category}").
		To(openpitrix.DescribeCategory).
		Doc(""))
	webservice.Route(webservice.GET("/categories").
		To(openpitrix.ListCategories).
		Doc(""))

	webservice.Route(webservice.GET("/attachments/{attachment}").
		To(openpitrix.DescribeAttachment).
		Doc(""))

	webservice.Route(webservice.POST("/repos").
		To(openpitrix.CreateRepo).
		Doc(""))
	webservice.Route(webservice.DELETE("/repos/{repo}").
		To(openpitrix.DeleteRepo).
		Doc(""))
	webservice.Route(webservice.PATCH("/repos/{repo}").
		Consumes(mimePatch...).
		To(openpitrix.PatchRepo).
		Doc(""))
	webservice.Route(webservice.GET("/repos/{repo}").
		To(openpitrix.DescribeRepo).
		Doc(""))
	webservice.Route(webservice.GET("/repos").
		To(openpitrix.ListRepos).
		Doc(""))
	webservice.Route(webservice.POST("/validate/repo").
		To(openpitrix.ValidateRepo).
		Doc(""))

	c.Add(webservice)

	return nil
}
