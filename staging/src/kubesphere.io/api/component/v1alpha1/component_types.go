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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComponentSpec defines the desired state of Component
type ComponentSpec struct {
	Enabled bool `json:"enabled"`
	// Selector is a label query over kinds that created by the application. It must match the component objects' labels.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
	// ComponentGroupKinds is a list of Kinds for Plugin's components
	ComponentGroupKinds []metav1.GroupKind `json:"componentKinds,omitempty"`
}

// APIServiceSpec defines the desired state of APIService
type APIServiceSpec struct {
	Group                 string   `json:"group,omitempty"`
	Version               string   `json:"version,omitempty"`
	InsecureSkipTLSVerify bool     `json:"insecureSkipTLSVerify,omitempty"`
	NonResourceURLs       []string `json:"nonResourceURLs,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	// `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
	// If unspecified, system trust roots on the apiserver are used.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`
}

// ComponentStatus defines the observed state of Component
type ComponentStatus struct {
}

// APIServiceStatus defines the observed state of APIService
type APIServiceStatus struct {
	Enabled bool `json:"enabled"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Component is the Schema for the components API
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="plugin",scope="Cluster"
type Component struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComponentSpec   `json:"spec,omitempty"`
	Status ComponentStatus `json:"status,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// APIService is the Schema for the components API
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="plugin",scope="Cluster"
type APIService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIServiceSpec   `json:"spec,omitempty"`
	Status APIServiceStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ComponentList contains a list of Component
type ComponentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Component `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// APIServiceList contains a list of APIService
type APIServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIService `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&Component{},
		&ComponentList{},
		&APIService{},
		&APIServiceList{},
	)
}
