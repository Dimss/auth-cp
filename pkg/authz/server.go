package authz

import (
	"context"
	"fmt"
	"github.com/AccessibleAI/cnvrg-cap/pkg/ingresscache"
	"github.com/AccessibleAI/cnvrg-cap/pkg/validator"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

type Service struct {
	authv3.UnimplementedAuthorizationServer
	cache *ingresscache.IngressCache
}

const tracerName = "authz"

func (s *Service) Check(c context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	var host, path string
	if request.Attributes != nil {
		host = request.Attributes.Request.Http.Host
		path = request.Attributes.Request.Http.Path
	}

	ctx, span := otel.Tracer(tracerName).Start(c, "check")
	span.SetAttributes(attribute.String("host", host), attribute.String("path", path))
	defer span.End()

	// init authentication context
	authCtx := validator.NewAuthContext(request, s.cache, nil)

	// execute validation chain
	span.AddEvent("starting validation")
	if valid, validatedIdentity := authCtx.Valid(ctx); valid {
		span.AddEvent("access allowed")
		AuthenticationChecksMetric.With(prometheus.Labels{"host": host, "path": path, "result": "allowed"}).Inc()
		return s.allowRequest(validatedIdentity)
	} else {
		span.RecordError(fmt.Errorf("authentication context is not valid, request denied"))
		span.SetStatus(codes.Error, fmt.Errorf("authentication failed").Error())
		AuthenticationChecksMetric.With(prometheus.Labels{"host": host, "path": path, "result": "denied"}).Inc()
		authCtx.Log.Info("authentication context is not valid, request denied")

		if !authCtx.RedirectDisabled() {
			return s.denyRequestWithRedirect(authCtx.RedirectUrl())
		} else {
			return s.denyRequestWithHtml(authCtx.ResponseBody())
		}
	}
}

func (s *Service) allowRequest(identityHeaders []*corev3.HeaderValueOption) (*authv3.CheckResponse, error) {
	resp := &authv3.CheckResponse{
		Status: &status.Status{Code: int32(rpc.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: identityHeaders,
			},
		},
		DynamicMetadata: nil,
	}
	return resp, nil
}

func (s *Service) denyRequestWithRedirect(redirectUrl string) (*authv3.CheckResponse, error) {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(rpc.UNAUTHENTICATED)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Found},
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "Location",
							Value: redirectUrl,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   "Cache-Control",
							Value: "private, max-age=0, no-store",
						},
					},
				},
			},
		},
	}, nil
}

func (s *Service) denyRequestWithHtml(httpBody string) (*authv3.CheckResponse, error) {

	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(rpc.UNAUTHENTICATED)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "Content-Type",
							Value: "text/html",
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   "Cache-Control",
							Value: "private, max-age=0, no-store",
						},
					},
				},
				Body: httpBody,
			},
		},
	}, nil
}

func NewAuthzService(grpcServer *grpc.Server, ingressType ingresscache.IngressType) {
	cache := ingresscache.NewIngressCache(ingressType)
	zap.S().Info("waiting for ingress cache readiness")
	<-cache.Notifier() // waiting for a cache to initialized
	zap.S().Info("ingress cache is ready")
	svc := &Service{
		UnimplementedAuthorizationServer: authv3.UnimplementedAuthorizationServer{},
		cache:                            cache, //todo: validate cache initialized
	}
	authv3.RegisterAuthorizationServer(grpcServer, svc)
}
