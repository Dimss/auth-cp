package authz

import (
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsNamespace  = "cnvrg"
	metricsSubsystems = "auth_proxy"
)

func init() {
	// Register standard server metrics and customized metrics to registry.
	Reg.MustRegister(GrpcMetrics, AuthenticationChecksMetric)
}

var (
	// Reg create a metrics registry.
	Reg = prometheus.NewRegistry()

	// GrpcMetrics create some standard server metrics.
	GrpcMetrics = grpc_prometheus.NewServerMetrics()

	AuthenticationChecksMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystems,
		Name:      "envoy_service_auth_v3_authorization_check_method_handle_count",
		Help:      "Total number of authorization checks performed",
	}, []string{"host", "path", "result"})
)
