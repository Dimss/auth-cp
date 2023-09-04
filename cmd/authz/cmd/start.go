package cmd

import (
	"context"
	"fmt"
	"github.com/AccessibleAI/cnvrg-cap/pkg/authz"
	"github.com/AccessibleAI/cnvrg-cap/pkg/ingresscache"
	"github.com/AccessibleAI/cnvrg-cap/pkg/validator"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	startCmd.PersistentFlags().StringP("bind-addr", "b", "0.0.0.0:50052", "bind to authz server")
	startCmd.PersistentFlags().StringP("auth-cookie", "c", "_cnvrg_auth", "oauth2-proxy cookie name")
	startCmd.PersistentFlags().StringP("auth-header", "", "authorization", "authentication header name")
	startCmd.PersistentFlags().BoolP("insecure-skip-verify", "s", true, "enable=true|disable=false https verification")
	startCmd.PersistentFlags().StringP("ingress-type", "i", "istio", fmt.Sprintf("one of %s|%s|%s",
		ingresscache.VsIngressType,
		ingresscache.K8sIngressType,
		ingresscache.RouteIngressType))
	startCmd.PersistentFlags().StringP("metrics-addr", "m", "0.0.0.0:2113", "metrics listen address")
	startCmd.PersistentFlags().BoolP("tracing-enabled", "t", false, "enable opentelemetry tracing")
	startCmd.PersistentFlags().StringP("jaeger-url", "", "", "jaeger url http://<host>:14268/api/traces, if not provided tracing is disabled")
	startCmd.PersistentFlags().StringSlice("jwks-servers", []string{}, "list of jwks server")
	startCmd.PersistentFlags().StringP("oauth2-token-issuer", "", "", "issuer of oauth2 token as it appears in iss claim")
	startCmd.PersistentFlags().StringSlice("oauth2-claims-validate", []string{}, "list of claims to validate on oauth2")
	startCmd.PersistentFlags().StringSlice("disable-validators", []string{}, fmt.Sprintf("validator types to disable - %s|%s|%s",
		validator.CapiType,
		validator.OAuthProxyType,
		validator.OAuth2Type))

	viper.BindPFlag("bind-addr", startCmd.PersistentFlags().Lookup("bind-addr"))
	viper.BindPFlag("auth-cookie", startCmd.PersistentFlags().Lookup("auth-cookie"))
	viper.BindPFlag("auth-header", startCmd.PersistentFlags().Lookup("auth-header"))
	viper.BindPFlag("insecure-skip-verify", startCmd.PersistentFlags().Lookup("insecure-skip-verify"))
	viper.BindPFlag("ingress-type", startCmd.PersistentFlags().Lookup("ingress-type"))
	viper.BindPFlag("metrics-addr", startCmd.PersistentFlags().Lookup("metrics-addr"))
	viper.BindPFlag("tracing-enabled", startCmd.PersistentFlags().Lookup("tracing-enabled"))
	viper.BindPFlag("jaeger-url", startCmd.PersistentFlags().Lookup("jaeger-url"))
	viper.BindPFlag("jwks-servers", startCmd.PersistentFlags().Lookup("jwks-servers"))
	viper.BindPFlag("oauth2-token-issuer", startCmd.PersistentFlags().Lookup("oauth2-token-issuer"))
	viper.BindPFlag("oauth2-claims-validate", startCmd.PersistentFlags().Lookup("oauth2-claims-validate"))
	viper.BindPFlag("disable-validators", startCmd.PersistentFlags().Lookup("disable-validators"))

	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start cnvrg authz server",
	Run: func(cmd *cobra.Command, args []string) {
		mux := http.NewServeMux()
		mux.HandleFunc("/profile", pprof.Profile)
		go func() { http.ListenAndServe(":7777", mux) }()

		startServer()
		// handle interrupts
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		for {
			select {
			case s := <-sigCh:
				zap.S().Infof("signal: %s, shutting down", s)
				zap.S().Info("bye bye 👋")
				os.Exit(0)
			}
		}
	},
}

func startServer() {
	var grpcServer *grpc.Server

	metricsInterceptor := authz.GrpcMetrics.UnaryServerInterceptor()

	lis, err := net.Listen("tcp", viper.GetString("bind-addr"))
	if err != nil {
		zap.S().Fatalf("failed to listen: %v", err)
	}

	grpcServerOption := grpc.UnaryInterceptor(metricsInterceptor)

	// adding global tracing provider
	if viper.GetBool("tracing-enabled") {
		propagatorInterceptor := otelgrpc.UnaryServerInterceptor(otelgrpc.WithPropagators(b3.New()))
		if viper.GetString("jaeger-url") == "" {
			zap.S().Fatal("tracing is enabled by jaeger URL is not set")
		}

		tp, err := tracerProvider(viper.GetString("jaeger-url"))
		if err != nil {
			zap.S().Fatal(err)
		}
		defer func() {
			if err := tp.Shutdown(context.Background()); err != nil {
				zap.S().Fatal(err)
			}
		}()
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})

		grpcServerOption = grpc.ChainUnaryInterceptor(metricsInterceptor, propagatorInterceptor)
	}

	grpcServer = grpc.NewServer(grpcServerOption)
	grpcprometheus.Register(grpcServer)
	authz.NewAuthzService(grpcServer, viper.GetString("ingress-type"))

	// Initialize all metrics.
	authz.GrpcMetrics.InitializeMetrics(grpcServer)
	authz.GrpcMetrics.EnableHandlingTimeHistogram()
	startMetrics()

	zap.S().Infof("grpc control plane server listening on %s", viper.GetString("bind-addr"))
	if err := grpcServer.Serve(lis); err != nil {
		zap.S().Fatal(err)
	}
}

func startMetrics() {
	addr := viper.GetString("metrics-addr")
	http.Handle("/metrics", promhttp.HandlerFor(authz.Reg, promhttp.HandlerOpts{}))
	go func() {
		zap.S().Infof("Prometheus metrics bind address %s", viper.GetString("metrics-addr"))
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			zap.S().Error("failed to start metrics server: ", err)
			return
		}
	}()
}

// tracerProvider returns an OpenTelemetry TracerProvider configured to use
// the Jaeger exporter that will send spans to the provided url. The returned
// TracerProvider will also use a Resource configured with all the information
// about the application.
func tracerProvider(url string) (*tracesdk.TracerProvider, error) {
	// Create the Jaeger exporter
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(url)))
	if err != nil {
		return nil, err
	}
	tp := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exp),

		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("authz"))),
	)
	return tp, nil
}
