package ingresscache

import (
	"context"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"regexp"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"strings"
)

const (
	capiAuthDataSecretName   = "cp-oauth-proxy-tokens-secret"
	ssoEnabledAnnotation     = "sso.cnvrg.io/enabled"
	skipAuthRoutesAnnotation = "sso.cnvrg.io/skipAuthRoutes"
	ssoCentralAnnotation     = "sso.cnvrg.io/central"
	upstreamSvcAnnotation    = "sso.cnvrg.io/upstream"
)

type DataCache struct {
	Name           string
	Host           string
	Namespace      string
	Annotations    map[string]string
	SsoEnabled     bool
	SkipAuthRoutes []*regexp.Regexp
	CentralSsoUrl  string
	UpstreamAddr   string
	CapiKey        string // legacy capi key
	CapiAuthData   string // legacy capi auth data
}

func NewDataCache(host, ns string, annotations map[string]string) *DataCache {
	// if the 'sso.cnvrg.io/enabled' annotation wasn't set,
	// no new entry will be added into the cache
	if _, cacheMe := annotations[ssoEnabledAnnotation]; !cacheMe {
		return nil
	}
	dc := &DataCache{
		Name:        strings.ReplaceAll(host, ".", "_"),
		Host:        host,
		Namespace:   ns,
		Annotations: annotations,
	}
	// set sso to true if enabled
	dc.setSso()
	// init skipAuthRoutes regexes
	dc.setSkipAuthRoutes()
	// set central sso url
	dc.setCentralSSO()
	// discover CAPI auth data if capi auth is set (legacy)
	dc.enrichCapiData()
	// discover upstream address and port
	dc.setUpstream()

	return dc
}

func (c *DataCache) setUpstream() {
	c.UpstreamAddr = c.Annotations[upstreamSvcAnnotation]
}

func (c *DataCache) setSso() {
	if enabled, ok := c.Annotations[ssoEnabledAnnotation]; ok {
		if enabled == "true" {
			c.SsoEnabled = true
		}
	}
}

func (c *DataCache) setCentralSSO() {
	if url, ok := c.Annotations[ssoCentralAnnotation]; ok && len(url) > 0 {
		if url[len(url)-1:] == "/" {
			url = url[:len(url)-1]
		}
		c.CentralSsoUrl = url
	} else {
		c.log().Infof("%s annotation is not set, will fail to redirect", ssoCentralAnnotation)
	}
}

func (c *DataCache) setSkipAuthRoutes() {
	if skipAuthRoutes, ok := c.Annotations[skipAuthRoutesAnnotation]; ok {

		for _, regexRow := range strings.Split(skipAuthRoutes, " ") {
			for _, regexStr := range strings.Split(regexRow, "\n") {

				finalRegex := strings.TrimSpace(regexStr)
				if len(finalRegex) == 0 {
					continue
				}
				compiledRegex, err := regexp.Compile(finalRegex)
				if err != nil {
					c.log().Errorf("regex: %s err: %s", finalRegex, err)
					continue
				}
				c.SkipAuthRoutes = append(c.SkipAuthRoutes, compiledRegex)
			}
		}
	}
}

func (c *DataCache) log() *zap.SugaredLogger {
	return zap.S().With("host", c.Host, "ns", c.Namespace)
}

func (c *DataCache) enrichCapiData() {
	l := c.log()
	rc, err := config.GetConfig()
	if err != nil {
		l.Error(err)
		return
	}
	sc, err := kubernetes.NewForConfig(rc)
	if err != nil {
		l.Error(err)
		return
	}

	sec, err := sc.CoreV1().Secrets(c.Namespace).Get(context.Background(), capiAuthDataSecretName, v1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		l.Infof("capi disabled, skipping enrichment")
		return
	} else if err != nil {
		l.Info(err)
		return
	}

	if _, ok := sec.Data["OAUTH_PROXY_API_KEY"]; !ok {
		l.Error("capi secret found, but missing expected key: OAUTH_PROXY_API_KEY")
		return
	}

	if _, ok := sec.Data["OAUTH_PROXY_API_AUTH_DATA"]; !ok {
		l.Error("capi secret found, but missing expected key: OAUTH_PROXY_API_AUTH_DATA")
		return
	}

	c.CapiKey = string(sec.Data["OAUTH_PROXY_API_KEY"])

	c.CapiAuthData = string(sec.Data["OAUTH_PROXY_API_AUTH_DATA"])

}
