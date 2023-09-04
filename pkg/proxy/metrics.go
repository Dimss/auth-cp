package proxy

import (
	"github.com/AccessibleAI/cnvrg-cap/pkg/ingresscache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	metricsNamespace  = "cnvrg"
	metricsSubsystems = "auth_proxy"
)

var commonLabels = []string{"host", "namespace", "upstream"}

var (
	skipAuthRoutesMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystems,
		Name:      "skip_auth_routes",
		Help:      "number of routes excluded",
	}, commonLabels)

	ssoEnabled = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystems,
		Name:      "sso_enabled",
		Help:      "sso enabled",
	}, commonLabels)

	capiKeyEnabled = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystems,
		Name:      "capi_key_enabled",
		Help:      "capi key enabled",
	}, commonLabels)

	capiAuthdataEnabled = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystems,
		Name:      "capi_authdata_enabled",
		Help:      "capi authdata enabled",
	}, commonLabels)
)

func Btoi(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func Strtoi(s string) float64 {
	if s != "" {
		return 1
	}
	return 0
}

func (p *CnvrgProxy) recordMetrics() {
	go func() {
		for {
			p.controlPlane.ingressCache.CacheStore().Range(func(host, dataCache any) bool {
				dc := dataCache.(*ingresscache.DataCache)
				labels := []string{dc.Host, dc.Namespace, dc.UpstreamAddr}
				skipAuthRoutesMetric.WithLabelValues(labels...).Set(float64(len(dc.SkipAuthRoutes)))
				ssoEnabled.WithLabelValues(labels...).Set(Btoi(dc.SsoEnabled))
				capiKeyEnabled.WithLabelValues(labels...).Set(Strtoi(dc.CapiKey))
				capiAuthdataEnabled.WithLabelValues(labels...).Set(Strtoi(dc.CapiAuthData))
				return true
			})

			time.Sleep(30 * time.Second)
		}
	}()
}

func (p *CnvrgProxy) startMetrics() {

	// start metric recorder
	p.recordMetrics()

	// start the exporter
	go func() {

		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/ready", func(writer http.ResponseWriter, request *http.Request) {
			// verify envoy is ready
			resp, err := http.Get("http://localhost:" + EnvoyAdminPort + "/ready")
			if err != nil {
				zap.S().Error("unable to access envoy admin readiness url, error: ", err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				zap.S().Error("envoy admin readiness returns status: ", resp.StatusCode)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			// verify control plan is listening
			c, err := net.Dial("tcp", ":"+strconv.Itoa(ControlPlanePort))
			if err != nil {
				zap.S().Error("controlPlan is not listening on port: ", ControlPlanePort)
			}
			defer c.Close()
			// all good
			writer.WriteHeader(http.StatusOK)
		})

		l, err := net.Listen("tcp", p.metricsAddr)
		if err != nil {
			zap.S().Error("failed to start metrics server: ", err)
			return
		}
		zap.S().Infof("serving metrics on http://%s/metrics", p.metricsAddr)
		zap.S().Infof("serving readiness on http://%s/ready", p.metricsAddr)
		if err := http.Serve(l, nil); err != nil {
			zap.S().Error(err)
			return
		}
	}()
}
