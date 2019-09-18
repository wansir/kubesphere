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
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog"
	"kubesphere.io/kubesphere/pkg/models"
	"kubesphere.io/kubesphere/pkg/server/params"
	cs "kubesphere.io/kubesphere/pkg/simple/client"
	"kubesphere.io/kubesphere/pkg/simple/client/openpitrix"
	"openpitrix.io/openpitrix/pkg/pb"
	opmodels "openpitrix.io/openpitrix/test/models"
	"strings"
)

type PatchRepoRequest struct {
	// app default status eg:[draft|active]
	AppDefaultStatus *string `json:"app_default_status,omitempty"`

	// category id
	CategoryID *string `json:"category_id,omitempty"`

	// credential of visiting the repository
	Credential *string `json:"credential,omitempty"`

	// repository description
	Description *string `json:"description,omitempty"`

	// a kv string, tags of server
	Labels *string `json:"labels,omitempty"`

	// repository name
	Name *string `json:"name,omitempty"`

	// runtime provider eg.[qingcloud|aliyun|aws|kubernetes]
	Providers []string `json:"providers"`

	// selectors of label
	Selectors *string `json:"selectors,omitempty"`

	// repository type
	Type *string `json:"type,omitempty"`

	// url of visiting the repository
	URL *string `json:"url,omitempty"`

	// visibility eg:[public|private]
	Visibility *string `json:"visibility,omitempty"`
}

func CreateRepo(request *opmodels.OpenpitrixCreateRepoRequest) (*opmodels.OpenpitrixCreateRepoResponse, error) {
	op, err := cs.ClientSets().OpenPitrix()
	if err != nil {
		klog.Error(err)
		return nil, err
	}
	r := &pb.CreateRepoRequest{
		Name:             &wrappers.StringValue{Value: request.Name},
		Description:      &wrappers.StringValue{Value: request.Description},
		Type:             &wrappers.StringValue{Value: request.Type},
		Url:              &wrappers.StringValue{Value: request.URL},
		Credential:       &wrappers.StringValue{Value: request.Credential},
		Visibility:       &wrappers.StringValue{Value: request.Visibility},
		Selectors:        &wrappers.StringValue{Value: request.Selectors},
		CategoryId:       &wrappers.StringValue{Value: request.CategoryID},
		AppDefaultStatus: &wrappers.StringValue{Value: request.AppDefaultStatus},
	}

	if request.Providers != nil {
		r.Providers = request.Providers
	}

	resp, err := op.Repo().CreateRepo(openpitrix.SystemContext(), r)
	if err != nil {
		klog.Error(err)
		return nil, err
	}
	return &opmodels.OpenpitrixCreateRepoResponse{
		RepoID: resp.GetRepoId().GetValue(),
	}, nil
}

func DeleteRepo(id string) error {
	op, err := cs.ClientSets().OpenPitrix()
	if err != nil {
		klog.Error(err)
		return err
	}
	_, err = op.Repo().DeleteRepos(openpitrix.SystemContext(), &pb.DeleteReposRequest{
		RepoId: []string{id},
	})
	if err != nil {
		klog.Error(err)
		return err
	}
	return nil
}

func PatchRepo(id string, request *PatchRepoRequest) error {
	op, err := cs.ClientSets().OpenPitrix()
	if err != nil {
		klog.Error(err)
		return err
	}
	modifyRepoRequest := &pb.ModifyRepoRequest{
		RepoId: &wrappers.StringValue{Value: id},
	}

	if request.Name != nil {
		modifyRepoRequest.Name = &wrappers.StringValue{Value: *request.Name}
	}
	if request.Description != nil {
		modifyRepoRequest.Description = &wrappers.StringValue{Value: *request.Description}
	}
	if request.Type != nil {
		modifyRepoRequest.Type = &wrappers.StringValue{Value: *request.Type}
	}
	if request.URL != nil {
		modifyRepoRequest.Url = &wrappers.StringValue{Value: *request.URL}
	}
	if request.Credential != nil {
		modifyRepoRequest.Credential = &wrappers.StringValue{Value: *request.Credential}
	}
	if request.Visibility != nil {
		modifyRepoRequest.Visibility = &wrappers.StringValue{Value: *request.Visibility}
	}
	if request.Selectors != nil {
		modifyRepoRequest.Selectors = &wrappers.StringValue{Value: *request.Selectors}
	}
	if request.CategoryID != nil {
		modifyRepoRequest.CategoryId = &wrappers.StringValue{Value: *request.CategoryID}
	}
	if request.AppDefaultStatus != nil {
		modifyRepoRequest.AppDefaultStatus = &wrappers.StringValue{Value: *request.AppDefaultStatus}
	}
	if request.Providers != nil {
		modifyRepoRequest.Providers = request.Providers
	}

	_, err = op.Repo().ModifyRepo(openpitrix.SystemContext(), modifyRepoRequest)
	if err != nil {
		klog.Error(err)
		return err
	}
	return nil
}

func DescribeRepo(id string) (*opmodels.OpenpitrixRepo, error) {
	op, err := cs.ClientSets().OpenPitrix()
	if err != nil {
		klog.Error(err)
		return nil, err
	}
	resp, err := op.Repo().DescribeRepos(openpitrix.SystemContext(), &pb.DescribeReposRequest{
		RepoId: []string{id},
		Limit:  1,
	})
	if err != nil {
		klog.Error(err)
		return nil, err
	}

	var repo *opmodels.OpenpitrixRepo

	if len(resp.RepoSet) > 0 {
		repo = convertRepo(resp.RepoSet[0])
		return repo, nil
	} else {
		err := status.New(codes.NotFound, "resource not found").Err()
		klog.Error(err)
		return nil, err
	}
}

func ListRepos(conditions *params.Conditions, orderBy string, reverse bool, limit, offset int) (*models.PageableResponse, error) {
	client, err := cs.ClientSets().OpenPitrix()

	if err != nil {
		klog.Error(err)
		return nil, err
	}

	req := &pb.DescribeReposRequest{}

	if keyword := conditions.Match["keyword"]; keyword != "" {
		req.SearchWord = &wrappers.StringValue{Value: keyword}
	}
	if status := conditions.Match["status"]; status != "" {
		req.Status = strings.Split(status, "|")
	}
	if typeStr := conditions.Match["type"]; typeStr != "" {
		req.Type = strings.Split(typeStr, "|")
	}
	if visibility := conditions.Match["visibility"]; visibility != "" {
		req.Visibility = strings.Split(visibility, "|")
	}
	if status := conditions.Match["status"]; status != "" {
		req.Status = strings.Split(status, "|")
	}
	if orderBy != "" {
		req.SortKey = &wrappers.StringValue{Value: orderBy}
	}
	req.Reverse = &wrappers.BoolValue{Value: reverse}
	req.Limit = uint32(limit)
	req.Offset = uint32(offset)
	resp, err := client.Repo().DescribeRepos(openpitrix.SystemContext(), req)
	if err != nil {
		klog.Error(err)
		return nil, err
	}

	items := make([]interface{}, 0)

	for _, item := range resp.RepoSet {
		items = append(items, convertRepo(item))
	}

	return &models.PageableResponse{Items: items, TotalCount: int(resp.TotalCount)}, nil
}

type ValidateRepoRequest struct {
	Type       string `json:"type"`
	Credential string `json:"credential"`
	Url        string `json:"url"`
}

func ValidateRepo(request *ValidateRepoRequest) (*opmodels.OpenpitrixValidateRepoResponse, error) {
	client, err := cs.ClientSets().OpenPitrix()

	if err != nil {
		klog.Error(err)
		return nil, err
	}

	resp, err := client.Repo().ValidateRepo(openpitrix.SystemContext(), &pb.ValidateRepoRequest{
		Type:       &wrappers.StringValue{Value: request.Type},
		Credential: &wrappers.StringValue{Value: request.Credential},
		Url:        &wrappers.StringValue{Value: request.Url},
	})

	if err != nil {
		klog.Error(err)
		return nil, err
	}

	return &opmodels.OpenpitrixValidateRepoResponse{
		ErrorCode: int64(resp.ErrorCode),
		Ok:        resp.Ok.Value,
	}, nil
}
