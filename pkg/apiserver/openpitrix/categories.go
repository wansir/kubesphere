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

func CreateCategory(req *restful.Request, resp *restful.Response) {
	createCategoryRequest := &opmodels.OpenpitrixCreateCategoryRequest{}
	err := req.ReadEntity(createCategoryRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	result, err := openpitrix.CreateCategory(createCategoryRequest)

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
func DeleteCategory(req *restful.Request, resp *restful.Response) {
	categoryId := req.PathParameter("category")

	err := openpitrix.DeleteCategory(categoryId)

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
func PatchCategory(req *restful.Request, resp *restful.Response) {
	var updateCategoryRequest openpitrix.PatchCategoryRequest
	categoryId := req.PathParameter("category")
	err := req.ReadEntity(updateCategoryRequest)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusBadRequest, errors.Wrap(err))
		return
	}

	err = openpitrix.PatchCategory(categoryId, &updateCategoryRequest)

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
func DescribeCategory(req *restful.Request, resp *restful.Response) {
	categoryId := req.PathParameter("category")

	result, err := openpitrix.DescribeCategory(categoryId)

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
func ListCategories(req *restful.Request, resp *restful.Response) {
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

	result, err := openpitrix.ListCategories(conditions, orderBy, reverse, limit, offset)

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
