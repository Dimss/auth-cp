package ingresscache

import (
	routev1 "github.com/openshift/api/route/v1"
	"go.uber.org/zap"
	"istio.io/client-go/pkg/apis/networking/v1beta1"
	v1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ingress struct{}

func (i *ingress) gvr() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "networking.k8s.io",
		Version:  "v1",
		Resource: "ingresses",
	}
}

func (i *ingress) parse(obj *unstructured.Unstructured) *DataCache {

	ingObj := &v1.Ingress{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, ingObj); err != nil {
		zap.S().Error(err)
		return nil
	}

	if len(ingObj.Spec.Rules) > 0 {
		return NewDataCache(ingObj.Spec.Rules[0].Host, ingObj.Namespace, ingObj.GetAnnotations())
	} else {
		return nil
	}
}

type vs struct{}

func (s *vs) gvr() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "networking.istio.io",
		Version:  "v1beta1",
		Resource: "virtualservices",
	}
}

func (s *vs) parse(obj *unstructured.Unstructured) *DataCache {
	vSvc := &v1beta1.VirtualService{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, vSvc); err != nil {
		zap.S().Error(err)
		return nil
	}
	if len(vSvc.Spec.Hosts) > 0 {
		return NewDataCache(vSvc.Spec.Hosts[0], vSvc.Namespace, vSvc.GetAnnotations())
	} else {
		return nil
	}
}

type route struct{}

func (r *route) gvr() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "route.openshift.io",
		Version:  "v1",
		Resource: "routes",
	}
}

func (r *route) parse(obj *unstructured.Unstructured) *DataCache {
	ocpRoute := &routev1.Route{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, ocpRoute); err != nil {
		zap.S().Error(err)
		return nil
	}
	return NewDataCache(ocpRoute.Spec.Host, ocpRoute.Namespace, ocpRoute.GetAnnotations())
}
