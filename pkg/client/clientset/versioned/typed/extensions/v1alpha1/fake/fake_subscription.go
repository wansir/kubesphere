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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1alpha1 "kubesphere.io/api/extensions/v1alpha1"
)

// FakeSubscriptions implements SubscriptionInterface
type FakeSubscriptions struct {
	Fake *FakeExtensionsV1alpha1
}

var subscriptionsResource = schema.GroupVersionResource{Group: "extensions.kubesphere.io", Version: "v1alpha1", Resource: "subscriptions"}

var subscriptionsKind = schema.GroupVersionKind{Group: "extensions.kubesphere.io", Version: "v1alpha1", Kind: "Subscription"}

// Get takes name of the subscription, and returns the corresponding subscription object, and an error if there is any.
func (c *FakeSubscriptions) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.Subscription, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(subscriptionsResource, name), &v1alpha1.Subscription{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Subscription), err
}

// List takes label and field selectors, and returns the list of Subscriptions that match those selectors.
func (c *FakeSubscriptions) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.SubscriptionList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(subscriptionsResource, subscriptionsKind, opts), &v1alpha1.SubscriptionList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.SubscriptionList{ListMeta: obj.(*v1alpha1.SubscriptionList).ListMeta}
	for _, item := range obj.(*v1alpha1.SubscriptionList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested subscriptions.
func (c *FakeSubscriptions) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(subscriptionsResource, opts))
}

// Create takes the representation of a subscription and creates it.  Returns the server's representation of the subscription, and an error, if there is any.
func (c *FakeSubscriptions) Create(ctx context.Context, subscription *v1alpha1.Subscription, opts v1.CreateOptions) (result *v1alpha1.Subscription, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(subscriptionsResource, subscription), &v1alpha1.Subscription{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Subscription), err
}

// Update takes the representation of a subscription and updates it. Returns the server's representation of the subscription, and an error, if there is any.
func (c *FakeSubscriptions) Update(ctx context.Context, subscription *v1alpha1.Subscription, opts v1.UpdateOptions) (result *v1alpha1.Subscription, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(subscriptionsResource, subscription), &v1alpha1.Subscription{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Subscription), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeSubscriptions) UpdateStatus(ctx context.Context, subscription *v1alpha1.Subscription, opts v1.UpdateOptions) (*v1alpha1.Subscription, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(subscriptionsResource, "status", subscription), &v1alpha1.Subscription{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Subscription), err
}

// Delete takes name of the subscription and deletes it. Returns an error if one occurs.
func (c *FakeSubscriptions) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(subscriptionsResource, name), &v1alpha1.Subscription{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeSubscriptions) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(subscriptionsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.SubscriptionList{})
	return err
}

// Patch applies the patch and returns the patched subscription.
func (c *FakeSubscriptions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.Subscription, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(subscriptionsResource, name, pt, data, subresources...), &v1alpha1.Subscription{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Subscription), err
}
