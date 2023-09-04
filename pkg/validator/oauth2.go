package validator

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/MicahParks/keyfunc"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang-jwt/jwt/v4"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"net/http"
	"strings"
	"sync"
	"time"
)

type OAuth2Validator struct {
	authCookieName     string
	authHeaderName     string
	claims             jwt.MapClaims
	claimsToValidate   []string
	ingressAnnotations map[string]string
	issuer             string
	log                *zap.Logger
	rawIdentityData    []byte
	requestHeaders     map[string]string
}

var jwksServers []*keyfunc.JWKS

const (
	TokenSigningAlgorithm = "RS256"
	TokenAlgorithmClaim   = "alg"
	TokenIssuerClaim      = "iss"
)

func initJwksKeyfuncs(jwksServerURLs []string) {
	if len(jwksServers) > 0 {
		return
	}
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ToDo(darsh):  this shouldn;t be here, temporary until solved "tls: failed to verify certificate: x509: certificate signed by unknown authority"
	}
	client := &http.Client{Transport: transCfg}
	// Create the keyfunc options. Use an error handler that logs. Refresh the JWKS when a JWT signed by an unknown KID
	// is found or at the specified interval. Rate limit these refreshes. Timeout the initial JWKS refresh request after
	// 10 seconds. This timeout is also used to create the initial context.Context for keyfunc.Get.
	options := keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			zap.S().Error(err)
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
		Client:            client,
	}

	for _, u := range jwksServerURLs {
		fmt.Println("adding jwks server:", u)
		// Create the JWKS from the resource at the given URL.
		jwks, err := keyfunc.Get(u, options)
		if err != nil {
			zap.S().Error(err)
		}
		jwksServers = append(jwksServers, jwks)
	}

}

func NewOAuth2Validator(
	authCookieName, authHeaderName, issuer string,
	claimsToValidate, jwksServerURLs []string,
	ingressAnnotations map[string]string,
	requestHeaders map[string]string,
	log *zap.Logger) *OAuth2Validator {

	initJwksKeyfuncs(jwksServerURLs)

	return &OAuth2Validator{
		authCookieName:     authCookieName,
		authHeaderName:     authHeaderName,
		claimsToValidate:   claimsToValidate,
		ingressAnnotations: ingressAnnotations,
		issuer:             issuer,
		log:                log,
		requestHeaders:     requestHeaders,
	}
}

func (v *OAuth2Validator) shouldValidate() bool {
	if _, ok := v.requestHeaders[v.authHeaderName]; ok {
		return true
	}
	if len(v.getAuthCookie()) > 0 {
		return true
	}
	return false
}

func (v *OAuth2Validator) isValid(ctx context.Context) bool {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "oauth2-validator")
	defer span.End()

	if !v.shouldValidate() {
		v.log.Info("not a oauth2-proxy based authentication, aborting")
		return false
	}

	var waitGroup sync.WaitGroup
	resCh := make(chan bool)
	b64JwtToken := v.jwtToken()
	// Validate JWT on each JWKS in parallel
	for _, jwks := range jwksServers {
		waitGroup.Add(1)
		j := jwks

		go func() {
			token, err := jwt.Parse(b64JwtToken, j.Keyfunc)
			if err != nil {
				v.log.Info("failed to parse the JWT", zap.Error(err))
				waitGroup.Done()
				return
			}

			if token.Valid {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					v.claims = claims
				} else {
					v.log.Error("failed to get claims from token", zap.Error(err))
					waitGroup.Done()
					return
				}
			}

			if token.Header[TokenAlgorithmClaim] != TokenSigningAlgorithm {
				v.log.Error("token signing algorithm is wrong")
				waitGroup.Done()
				return
			}

			if v.claims[TokenIssuerClaim].(string) != v.issuer {
				v.log.Error("issuer claim is not as expected", zap.String("claim_name", TokenIssuerClaim), zap.String("want", v.issuer), zap.String("got", v.claims[TokenIssuerClaim].(string)))
				waitGroup.Done()
				return
			}

			if !v.CustomClaimsValid() {
				v.log.Error("custom claims are not as expected")
				waitGroup.Done()
				return
			}

			resCh <- true
			waitGroup.Done()
			return
		}()
	}

	go func() {
		waitGroup.Wait()
		resCh <- false
	}()

	result := <-resCh
	return result
}

func (v *OAuth2Validator) ValidatedIdentity() (identityHeaders []*corev3.HeaderValueOption) {
	var (
		email string
	)

	if e, ok := v.claims["emails"]; ok {
		email = e.([]interface{})[0].(string)
	} else {
		v.log.Info("token doesn't contain email claims")
		email = ""
	}

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "X-Forwarded-Email",
			Value: email,
		},
		Append: wrapperspb.Bool(false),
	})

	return
}

func (v *OAuth2Validator) jwtToken() string {
	if authCookieValue := v.getAuthCookie(); len(authCookieValue) > 0 {
		v.log = v.log.With(zap.Field{Key: "authType", Type: zapcore.StringType, String: "cookie"})
		token := strings.Split(authCookieValue, "=")
		if len(token) < 1 {
			v.log.Error("wrong cookie format")
			return ""
		}
		return token[1]
	}
	return strings.TrimSpace(strings.ReplaceAll(v.requestHeaders[v.authHeaderName], "Bearer", ""))

}

func (v *OAuth2Validator) getAuthCookie() string {
	for _, cookie := range strings.Split(v.requestHeaders["cookie"], ";") {
		if strings.Contains(cookie, v.authCookieName) {
			return cookie
		}
	}
	return ""
}

func (v *OAuth2Validator) CustomClaimsValid() bool {
	for _, c := range v.claimsToValidate {
		var annotation string
		var claim string

		if cl, ok := v.claims[c]; ok {
			claim = cl.(string)
		} else {
			v.log.Error("claim not presented in token", zap.String("claim_name", c))
			return false
		}

		if a, ok := v.ingressAnnotations[c]; ok {
			annotation = a
		} else {
			v.log.Error("annotation is not present on VS", zap.String("annotation_name", c))
		}

		if annotation != claim {
			v.log.Error("claim is invalid", zap.String("claim_name", c), zap.String("want", annotation), zap.String("got", v.claims[c].(string)))
			v.log.Error("")
			return false
		}
	}
	return true
}
