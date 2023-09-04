package validator

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"github.com/AccessibleAI/cnvrg-cap/pkg/ingresscache"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"sync"
	"text/template"
)

//go:embed  tmpl/*
var tmpl embed.FS

type validator interface {
	isValid(context.Context) bool
	ValidatedIdentity() (identityHeaders []*corev3.HeaderValueOption)
}

const (
	CapiType       = "capi"
	OAuthProxyType = "oauthproxy"
	OAuth2Type     = "oauth2"

	DisableRedirectAnnotation = "sso.cnvrg.io/disable-redirect"

	TokenPageTmpl = "tmpl/tokenpage.tpl"
)

type AuthContext struct {
	opts    *Options
	cache   *ingresscache.IngressCache
	request *authv3.CheckRequest
	Log     *zap.Logger
}

func (ac *AuthContext) capiKey() []byte {
	capiKey := ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).CapiKey
	if len(capiKey) == 0 {
		ac.Log.Error("capi key is empty, the capi authentication flow will fail")
		return nil
	}
	return []byte(capiKey)
}

func (ac *AuthContext) capiAuthData() []byte {
	authData := ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).CapiAuthData
	if len(authData) == 0 {
		ac.Log.Error("capi auth data is empty, the capi authentication flow will fail")
		return nil
	}
	return []byte(authData)
}

func (ac *AuthContext) Valid(ctx context.Context) (bool, []*corev3.HeaderValueOption) {
	span := trace.SpanFromContext(ctx)

	// skip authentication validation if sso disabled for current host
	if !ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).SsoEnabled {
		span.AddEvent("sso disabled")
		ac.Log.Info("sso disabled")
		return true, nil
	}

	// skip authentication if path in skip auth routes
	if ac.skipAuthRoute() {
		span.AddEvent("skipping auth, path match found")
		ac.Log.Info("skipping auth, path match found")
		return true, nil
	}

	if ac.request.Attributes.Request.Http.Method == http.MethodOptions {
		span.AddEvent("skipping auth, method is OPTIONS")
		return true, nil
	}

	var validators []validator

	// oauth2 proxy based validation for oauth proxy cookie or bearer token
	if !ac.opts.validatorDisabled(OAuthProxyType) {
		validators = append(validators, NewOauthProxyValidator(
			ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).CentralSsoUrl,
			ac.opts.AuthCookie,
			ac.opts.AuthHeader,
			ac.request.Attributes.Request.Http.Headers,
			ac.Log,
		))
	}

	if !ac.opts.validatorDisabled(OAuth2Type) {
		validators = append(validators, NewOAuth2Validator(
			ac.opts.AuthCookie,
			ac.opts.AuthHeader,
			ac.opts.Oauth2TokenIssuer,
			ac.opts.Oauth2ClaimsValidate,
			ac.opts.JwksServerURLs,
			ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).Annotations,
			ac.request.Attributes.Request.Http.Headers,
			ac.Log,
		))
	}

	// cnvrg legacy capi token validation for CAPI tokens
	if !ac.opts.validatorDisabled(CapiType) {
		validators = append(validators, NewCapiValidator(
			ac.request.Attributes.Request.Http.Headers["authorization"],
			ac.capiKey(),
			ac.capiAuthData(),
			ac.Log,
		))
	}

	type IdentityHeaders []*corev3.HeaderValueOption
	var wg sync.WaitGroup

	type ValidationRes struct {
		valid   bool
		headers IdentityHeaders
	}
	resCh := make(chan ValidationRes)

	for _, val := range validators {
		wg.Add(1)
		v := val
		go func() {
			if v.isValid(ctx) {
				ac.Log.Info("authentication context is valid, request allowed")
				resCh <- ValidationRes{
					valid:   true,
					headers: v.ValidatedIdentity(),
				}
				return
			} else {
				wg.Done()
				return
			}
		}()
	}

	go func() {
		wg.Wait()
		resCh <- ValidationRes{
			valid:   false,
			headers: nil,
		}
	}()

	result := <-resCh
	return result.valid, result.headers
}

func (ac *AuthContext) skipAuthRoute() bool {
	skipAuthRoutes := ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).SkipAuthRoutes
	for _, compliedRegex := range skipAuthRoutes {
		if compliedRegex.Match([]byte(ac.request.Attributes.Request.Http.Path)) {
			return true
		}
	}
	return false
}

func (ac *AuthContext) RedirectUrl() string {
	redirectUrl := fmt.Sprintf("%s/oauth2/sign_in",
		ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).CentralSsoUrl,
	)
	ac.Log.Sugar().Infof("redirect to: %s", redirectUrl)
	return redirectUrl
}

func (ac *AuthContext) ResponseBody() string {
	var tpl bytes.Buffer
	f, err := tmpl.ReadFile(TokenPageTmpl)
	if err != nil {
		zap.S().Error(err)
	}
	t, err := template.New("config").
		Option("missingkey=error").
		Parse(string(f))

	if err != nil {
		zap.S().Error(err)
		return ""
	}
	templateData := map[string]string{
		"AuthCookie": ac.opts.AuthCookie,
	}
	if err := t.Execute(&tpl, templateData); err != nil {
		zap.S().Fatal(err)
	}

	return string(tpl.Bytes())
}

func (ac *AuthContext) RedirectDisabled() bool {
	redirectDisabled, ok := ac.cache.HostDataCache(ac.request.Attributes.Request.Http.Host).Annotations[DisableRedirectAnnotation]
	if !ok || redirectDisabled == "false" {
		return false
	}
	return true
}

func NewAuthContext(r *authv3.CheckRequest, cache *ingresscache.IngressCache, opts *Options) *AuthContext {
	var options *Options
	if opts != nil {
		options = opts
	} else {
		options = NewOptionsFromFlags()
	}
	return &AuthContext{
		request: r,
		cache:   cache,
		opts:    options,
		Log: zap.L().With(
			[]zap.Field{
				{
					Key:    "host",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Host,
				},
				{
					Key:    "path",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Path,
				},
				{
					Key:    "schema",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Scheme,
				},
				{
					Key:    "rid",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Headers["x-request-id"],
				},
			}...,
		),
	}
}
