package validator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/dnscache"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

type OauthProxyValidator struct {
	proxyUrl        string
	authCookieName  string
	authHeaderName  string
	requestHeaders  map[string]string
	log             *zap.Logger
	rawIdentityData []byte
	retryableClient *retryablehttp.Client
}

const tracerName = "validator"

var retryablehttpClient *retryablehttp.Client

var resolver = &dnscache.Resolver{}

func httpClient() *retryablehttp.Client {

	if retryablehttpClient != nil {
		return retryablehttpClient
	}

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			resolver.RefreshWithOptions(dnscache.ResolverRefreshOptions{ClearUnused: true, PersistOnFailure: true})
		}
	}()
	// share http client across the instance
	retryablehttpClient = retryablehttp.NewClient()
	retryablehttpClient.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("insecure-skip-verify")},
			DialContext: func(ctx context.Context, network string, addr string) (conn net.Conn, err error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := resolver.LookupHost(ctx, host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					var dialer net.Dialer
					conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
					if err == nil {
						break
					}
				}
				return
			},
		},
	}
	retryablehttpClient.RetryMax = 5
	retryablehttpClient.RetryWaitMax = time.Second
	return retryablehttpClient
}

func NewOauthProxyValidator(proxyUrl, authCookieName, authHeaderName string, requestHeaders map[string]string, log *zap.Logger) *OauthProxyValidator {

	return &OauthProxyValidator{
		proxyUrl:        proxyUrl,
		authCookieName:  authCookieName,
		authHeaderName:  authHeaderName,
		requestHeaders:  requestHeaders,
		log:             log,
		retryableClient: httpClient(),
	}
}

func (v *OauthProxyValidator) shouldValidate() bool {
	if _, ok := v.requestHeaders[v.authHeaderName]; ok {
		return true
	}
	if len(v.getAuthCookie()) > 0 {
		return true
	}
	return false
}

func (v *OauthProxyValidator) isValid(ctx context.Context) bool {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "oauth-central-sso-userinfo", trace.WithAttributes(semconv.PeerServiceKey.String(v.proxyUrl)))
	defer span.End()

	if !v.shouldValidate() {
		v.log.Info("not a oauth2-proxy based authentication, aborting")
		return false
	}

	ctx = httptrace.WithClientTrace(ctx, otelhttptrace.NewClientTrace(ctx))
	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", v.proxyUrl+"/oauth2/userinfo", nil)
	if err != nil {
		v.log.Sugar().Error(err)
	}
	req.Header.Set(v.authHeader())
	resp, err := v.retryableClient.Do(req)
	if err != nil {
		v.log.Sugar().Error(err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("auth not valid, bad status code: %d", resp.StatusCode)
		err = fmt.Errorf(errMsg)
		v.log.Sugar().Info(errMsg)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false
	}
	v.rawIdentityData, err = io.ReadAll(resp.Body)
	if err != nil {
		v.log.Sugar().Error(err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	v.log.Info("valid")

	return true
}

func (v *OauthProxyValidator) ValidatedIdentity() (identityHeaders []*corev3.HeaderValueOption) {
	authData := struct {
		Email  string
		Groups []string
	}{}

	if err := json.Unmarshal(v.rawIdentityData, &authData); err != nil {
		v.log.Sugar().Errorf("failed to parse /oauth2/userinfo response, err: %s", err)
		return
	}

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "X-Forwarded-Email",
			Value: authData.Email,
		},
		Append: wrapperspb.Bool(false),
	})

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "X-Forwarded-Groups",
			Value: strings.Join(authData.Groups, ","),
		},
		Append: wrapperspb.Bool(false),
	})

	return
}

func (v *OauthProxyValidator) authHeader() (key, value string) {
	if authCookieValue := v.getAuthCookie(); len(authCookieValue) > 0 {
		v.log = v.log.With(zap.Field{Key: "authType", Type: zapcore.StringType, String: "cookie"})
		return "cookie", authCookieValue
	}
	v.log = v.log.With(zap.Field{Key: "authType", Type: zapcore.StringType, String: "bearer"})
	if !strings.Contains(v.requestHeaders[v.authHeaderName], "Bearer") {
		return "authorization", fmt.Sprintf("Bearer %s", v.requestHeaders[v.authHeaderName])
	}
	return "authorization", v.requestHeaders[v.authHeaderName]

}

func (v *OauthProxyValidator) getAuthCookie() string {
	for _, cookie := range strings.Split(v.requestHeaders["cookie"], ";") {
		if strings.Contains(cookie, v.authCookieName) {
			return cookie
		}
	}
	return ""
}
