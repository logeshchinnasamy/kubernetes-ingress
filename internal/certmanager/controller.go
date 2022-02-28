/*
Copyright 2020 The cert-manager Authors.
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

package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	vslisters "github.com/nginxinc/kubernetes-ingress/pkg/client/listers/configuration/v1"
	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	vsinformers "github.com/nginxinc/kubernetes-ingress/pkg/client/informers/externalversions"
	k8s_nginx "github.com/nginxinc/kubernetes-ingress/pkg/client/clientset/versioned"
)

const (
	ControllerName = "vs-cm-shim"

	// resyncPeriod is set to 10 hours across cert-manager. These 10 hours come
	// from a discussion on the controller-runtime project that boils down to:
	// never change this without an explicit reason.
	// https://github.com/kubernetes-sigs/controller-runtime/pull/88#issuecomment-408500629
	resyncPeriod = 10 * time.Hour
)

type cmController struct {
	vsLister 	  vslisters.VirtualServerLister
	sync          SyncFn

	// For testing purposes.
	queue workqueue.RateLimitingInterface
}

func (c *cmController) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {

	log := logf.FromContext(ctx.RootContext, ControllerName)

	handlers := createVirtualServerHandlers(c.queue)
	confClient, _ := k8s_nginx.NewForConfig(ctx.RESTConfig)

	sharedInformerFactory := vsinformers.NewSharedInformerFactoryWithOptions(confClient, resyncPeriod)
	informer := sharedInformerFactory.K8s().V1().VirtualServers().Informer()
	informer.AddEventHandler(handlers)
	c.vsLister = sharedInformerFactory.K8s().V1().VirtualServers().Lister()

	c.sync = SyncFnFor(ctx.Recorder, log, ctx.CMClient, ctx.SharedInformerFactory.Certmanager().V1().Certificates().Lister(), ctx.IngressShimOptions)

	// Even thought the Gateway controller already re-queues the Gateway after
	// creating a child Certificate, we still re-queue the Gateway when we
	// receive an "Add" event for the Certificate (the workqueue de-duplicates
	// keys, so we should not worry).
	//
	// Regarding "Update" events on Certificates, we need to requeue the parent
	// Gateway because we need to check if the Certificate is still up to date.
	//
	// Regarding "Deleted" events on Certificates, we requeue the parent Gateway
	// to immediately recreate the Certificate when the Certificate is deleted.
	ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificateHandler(c.queue),
	})

	mustSync := []cache.InformerSynced{
		informer.HasSynced,
		ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().HasSynced,
	}

	return c.queue, mustSync, nil
}

func (c *cmController) ProcessItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	crt, err := c.vsLister.VirtualServers(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("virtualServer '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.sync(ctx, crt)
}

// Whenever a Certificate gets updated, added or deleted, we want to reconcile
// its parent Gateway. This parent Gateway is called "controller object". For
// example, the following Certificate "cert-1" is controlled by the Gateway
// "gateway-1":
//
//     kind: Certificate
//     metadata:                                           Note that the owner
//       namespace: cert-1                                 reference does not
//       ownerReferences:                                  have a namespace,
//       - controller: true                                since owner refs
//         apiVersion: networking.x-k8s.io/v1alpha1        only work inside
//         kind: Gateway                                   the same namespace.
//         name: gateway-1
//         blockOwnerDeletion: true
//         uid: 7d3897c2-ce27-4144-883a-e1b5f89bd65a
func certificateHandler(queue workqueue.RateLimitingInterface) func(obj interface{}) {
	return func(obj interface{}) {
		crt, ok := obj.(*cmapi.Certificate)
		if !ok {
			runtime.HandleError(fmt.Errorf("not a Certificate object: %#v", obj))
			return
		}

		ref := metav1.GetControllerOf(crt)
		if ref == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		// We don't check the apiVersion
		// because there is no chance that another object called "VirtualServer" be
		// the controller of a Certificate.
		if ref.Kind != "VirtualServer" {
			return
		}

		queue.Add(crt.Namespace + "/" + ref.Name)
	}
}

func createVirtualServerHandlers(queue workqueue.RateLimitingInterface) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			vs := obj.(*conf_v1.VirtualServer)
			queue.Add(vs)
		},
		DeleteFunc: func(obj interface{}) {
			vs, isVs := obj.(*conf_v1.VirtualServer)
			if !isVs {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					runtime.HandleError(fmt.Errorf("received unexpected object: %#v", obj))
					return
				}
				vs, ok = deletedState.Obj.(*conf_v1.VirtualServer)
				if !ok {
					runtime.HandleError(fmt.Errorf("DeletedFinalStateUnknown contained non-VirtualServer object:: %#v", obj))
					return
				}
			}
			queue.Add(vs)
		},
		UpdateFunc: func(old, cur interface{}) {
			curVs := cur.(*conf_v1.VirtualServer)
			oldVs := old.(*conf_v1.VirtualServer)
			if !reflect.DeepEqual(oldVs.Spec.TLS.CertManager, curVs.Spec.TLS.CertManager) {
				queue.Add(curVs)
			}
		},
	}
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&cmController{queue: workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)}).
			Complete()
	})
}
