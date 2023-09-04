package cmd

import (
	"fmt"
	"github.com/AccessibleAI/cnvrg-cap/pkg/ingresscache"
	"github.com/AccessibleAI/cnvrg-cap/pkg/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	startCmd.PersistentFlags().StringP("envoy-path", "p", "/usr/local/bin/envoy", "path to envoy binary")
	startCmd.PersistentFlags().StringP("listener-addr", "l", "0.0.0.0:8888", "listener bind address")
	startCmd.PersistentFlags().StringP("authz-addr", "z", "127.0.0.1:50052", "authz server address:port")
	startCmd.PersistentFlags().BoolP("enable-authz", "e", true, "enabled or disable authz callback")
	startCmd.PersistentFlags().IntP("upstream-timeout", "t", 10, "timeout for upstream request")
	startCmd.PersistentFlags().StringP("ingress-type", "", "istio", fmt.Sprintf("one of %s|%s|%s",
		ingresscache.VsIngressType,
		ingresscache.K8sIngressType,
		ingresscache.RouteIngressType))
	startCmd.PersistentFlags().StringP("metrics-addr", "", "0.0.0.0:2112", "metrics & readiness listen address")
	startCmd.PersistentFlags().BoolP("tracing-enabled", "", false, "enable opentelemetry tracing")
	startCmd.PersistentFlags().StringP("jaeger-addr", "", "", "jaeger server address:port, port should accept zipkin spans, default port for jaeger - 9411")

	viper.BindPFlag("envoy-path", startCmd.PersistentFlags().Lookup("envoy-path"))
	viper.BindPFlag("listener-addr", startCmd.PersistentFlags().Lookup("listener-addr"))
	viper.BindPFlag("authz-addr", startCmd.PersistentFlags().Lookup("authz-addr"))
	viper.BindPFlag("enable-authz", startCmd.PersistentFlags().Lookup("enable-authz"))
	viper.BindPFlag("upstream-timeout", startCmd.PersistentFlags().Lookup("upstream-timeout"))
	viper.BindPFlag("ingress-type", startCmd.PersistentFlags().Lookup("ingress-type"))
	viper.BindPFlag("metrics-addr", startCmd.PersistentFlags().Lookup("metrics-addr"))
	viper.BindPFlag("tracing-enabled", startCmd.PersistentFlags().Lookup("tracing-enabled"))
	viper.BindPFlag("jaeger-addr", startCmd.PersistentFlags().Lookup("jaeger-addr"))

	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start envoy server",
	Run: func(cmd *cobra.Command, args []string) {

		zap.S().Info("running envoy-control plane server")

		if viper.GetBool("tracing-enabled") && viper.GetString("jaeger-addr") == "" {
			zap.S().Error("tracing is enabled but jaeger address is not set")
		}

		controlPlane := proxy.NewEnvoyControlPlane(
			ingresscache.NewIngressCache(viper.GetString("ingress-type")),
			viper.GetInt64("upstream-timeout"),
			viper.GetString("authz-addr"),
			viper.GetString("listener-addr"),
		)
		if !viper.GetBool("enable-authz") {
			controlPlane.DisabledAuthz()
		}

		controlPlane.DumpConfig()
		proxy := proxy.NewDefaultCnvrgProxy(
			viper.GetString("envoy-path"),
			viper.GetString("metrics-addr"),
			controlPlane,
		)
		proxy.Run()
		controlPlane.Run()

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
