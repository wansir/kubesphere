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

package openpitrix

import (
	"github.com/emicklei/go-restful"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog"
	"kubesphere.io/kubesphere/pkg/models/openpitrix"
	"kubesphere.io/kubesphere/pkg/server/errors"
	"kubesphere.io/kubesphere/pkg/server/params"
	"kubesphere.io/kubesphere/pkg/simple/client"
	"net/http"
	opmodels "openpitrix.io/openpitrix/test/models"
)

func GetAppVersionPackage(req *restful.Request, resp *restful.Response) {
	appId := req.PathParameter("app")
	versionId := req.PathParameter("version")

	result, err := openpitrix.GetAppVersionPackage(appId, versionId)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if err != nil {
		klog.Errorln(err)
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func DoAppVersionAction(req *restful.Request, resp *restful.Response) {
	var doActionRequest openpitrix.AppVersionActionRequest
	err := req.ReadEntity(&doActionRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	versionId := req.PathParameter("version")

	err = openpitrix.DoAppVersionAction(versionId, &doActionRequest)
	if status.Code(err) == codes.NotFound {
		resp.WriteHeaderAndEntity(http.StatusNotFound, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.InvalidArgument {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	if err != nil {
		klog.Errorln(err)
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(errors.None)
}

func GetAppVersionFiles(req *restful.Request, resp *restful.Response) {
	var getAppVersionFilesRequest openpitrix.GetAppVersionFilesRequest
	err := req.ReadEntity(&getAppVersionFilesRequest)
	versionId := req.PathParameter("version")
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}
	result, err := openpitrix.GetAppVersionFiles(versionId, &getAppVersionFilesRequest)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.NotFound {
		resp.WriteHeaderAndEntity(http.StatusNotFound, errors.Wrap(err))
		return
	}

	if err != nil {
		klog.Errorln(err)
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func ListAppVersionAudits(req *restful.Request, resp *restful.Response) {
	conditions, err := params.ParseConditions(req.QueryParameter(params.ConditionsParam))
	orderBy := req.QueryParameter(params.OrderByParam)
	limit, offset := params.ParsePaging(req.QueryParameter(params.PagingParam))
	reverse := params.ParseReverse(req)
	appId := req.PathParameter("app")
	versionId := req.PathParameter("version")
	if orderBy == "" {
		orderBy = "status_time"
		reverse = true
	}
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}
	conditions.Match["app"] = appId
	if versionId != "" {
		conditions.Match["version"] = versionId
	}

	result, err := openpitrix.ListAppVersionAudits(conditions, orderBy, reverse, limit, offset)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if err != nil {
		klog.Errorln(err)
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func ListReviews(req *restful.Request, resp *restful.Response) {
	conditions, err := params.ParseConditions(req.QueryParameter(params.ConditionsParam))
	orderBy := req.QueryParameter(params.OrderByParam)
	limit, offset := params.ParsePaging(req.QueryParameter(params.PagingParam))
	reverse := params.ParseReverse(req)
	if orderBy == "" {
		orderBy = "status_time"
		reverse = true
	}
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	result, err := openpitrix.ListAppVersionReviews(conditions, orderBy, reverse, limit, offset)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if err != nil {
		klog.Errorln(err)
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func ListAppVersions(req *restful.Request, resp *restful.Response) {
	conditions, err := params.ParseConditions(req.QueryParameter(params.ConditionsParam))
	orderBy := req.QueryParameter(params.OrderByParam)
	limit, offset := params.ParsePaging(req.QueryParameter(params.PagingParam))
	reverse := params.ParseReverse(req)
	appId := req.PathParameter("app")
	if orderBy == "" {
		orderBy = "create_time"
		reverse = true
	}
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}
	conditions.Match["app"] = appId

	result, err := openpitrix.ListAppVersions(conditions, orderBy, reverse, limit, offset)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if err != nil {
		klog.Errorln(err)
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func ListApps(req *restful.Request, resp *restful.Response) {
	conditions, err := params.ParseConditions(req.QueryParameter(params.ConditionsParam))
	orderBy := req.QueryParameter(params.OrderByParam)
	limit, offset := params.ParsePaging(req.QueryParameter(params.PagingParam))
	reverse := params.ParseReverse(req)
	if orderBy == "" {
		orderBy = "create_time"
		reverse = true
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	result, err := openpitrix.ListApps(conditions, orderBy, reverse, limit, offset)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if err != nil {
		klog.Errorln(err)
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func PatchApp(req *restful.Request, resp *restful.Response) {

	var patchAppRequest openpitrix.PatchAppRequest
	err := req.ReadEntity(&patchAppRequest)
	appId := req.PathParameter("app")

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	err = openpitrix.PatchApp(appId, &patchAppRequest)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.NotFound {
		resp.WriteHeaderAndEntity(http.StatusNotFound, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.InvalidArgument {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(errors.None)
}

func DescribeApp(req *restful.Request, resp *restful.Response) {
	appId := req.PathParameter("app")

	result, err := openpitrix.DescribeApp(appId)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.NotFound {
		resp.WriteHeaderAndEntity(http.StatusNotFound, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func DeleteApp(req *restful.Request, resp *restful.Response) {
	appId := req.PathParameter("app")

	err := openpitrix.DeleteApp(appId)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.NotFound {
		resp.WriteHeaderAndEntity(http.StatusNotFound, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(errors.None)
}

func CreateApp(req *restful.Request, resp *restful.Response) {
	createAppRequest := &opmodels.OpenpitrixCreateAppRequest{}
	err := req.ReadEntity(createAppRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	result, err := openpitrix.CreateApp(createAppRequest)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.InvalidArgument {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func CreateAppVersion(req *restful.Request, resp *restful.Response) {
	var createAppVersionRequest opmodels.OpenpitrixCreateAppVersionRequest
	err := req.ReadEntity(&createAppVersionRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}
	// override app id
	appId := req.PathParameter("app")
	createAppVersionRequest.AppID = appId

	result, err := openpitrix.CreateAppVersion(&createAppVersionRequest)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.InvalidArgument {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func ValidatePackage(req *restful.Request, resp *restful.Response) {
	validatePackageRequest := &opmodels.OpenpitrixValidatePackageRequest{}
	err := req.ReadEntity(validatePackageRequest)

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	result, err := openpitrix.ValidatePackage(validatePackageRequest)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.InvalidArgument {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}

func PatchAppVersion(req *restful.Request, resp *restful.Response) {

	var patchAppVersionRequest openpitrix.PatchAppVersionRequest
	err := req.ReadEntity(&patchAppVersionRequest)
	versionId := req.PathParameter("version")

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	err = openpitrix.PatchAppVersion(versionId, &patchAppVersionRequest)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.InvalidArgument {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(errors.None)
}

func DeleteAppVersion(req *restful.Request, resp *restful.Response) {
	versionId := req.PathParameter("version")

	err := openpitrix.DeleteAppVersion(versionId)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.NotFound {
		resp.WriteHeaderAndEntity(http.StatusNotFound, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(errors.None)
}

func DescribeAppVersion(req *restful.Request, resp *restful.Response) {
	versionId := req.PathParameter("version")

	result, err := openpitrix.DescribeAppVersion(versionId)

	if _, notEnabled := err.(client.ClientSetNotEnabledError); notEnabled {
		resp.WriteHeaderAndEntity(http.StatusNotImplemented, errors.Wrap(err))
		return
	}

	if status.Code(err) == codes.NotFound {
		resp.WriteHeaderAndEntity(http.StatusNotFound, errors.Wrap(err))
		return
	}

	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusInternalServerError, errors.Wrap(err))
		return
	}

	resp.WriteEntity(result)
}
