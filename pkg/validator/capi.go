package validator

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
	"strings"
)

type CapiValidator struct {
	capiToken       string
	capiKey         []byte
	capiAuthData    []byte
	log             *zap.Logger
	rawIdentityData []byte
}

func NewCapiValidator(capiToken string, key, authData []byte, log *zap.Logger) *CapiValidator {
	return &CapiValidator{
		capiToken:    capiToken,
		capiKey:      key,
		capiAuthData: authData,
		log:          log,
	}
}

func (c *CapiValidator) isValid(ctx context.Context) bool {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "capi")
	defer span.End()
	if !strings.Contains(c.capiToken, "CAPI ") {
		c.log.Info("not a capi token, aborting validation check")
		span.AddEvent("not a capi token, aborting validation check")
		return false
	}

	token, err := hex.DecodeString(strings.ReplaceAll(c.capiToken, "CAPI ", ""))

	ci, err := aes.NewCipher(c.capiKey)
	if err != nil {
		c.log.Sugar().Error(err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		c.log.Sugar().Error(err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	nonceSize := gcm.NonceSize()
	if len(token) < nonceSize {
		errMsg := "bad token, token < nonceSize"
		c.log.Error(errMsg)
		span.RecordError(fmt.Errorf(errMsg))
		span.SetStatus(codes.Error, fmt.Errorf(errMsg).Error())
		return false
	}

	nonce, cipherText := token[:nonceSize], token[nonceSize:]

	// the auth data seems to be not needed, though, that's the legacy
	// https://crypto.stackexchange.com/questions/89303/what-is-auth-data-in-aes-gcm
	c.rawIdentityData, err = gcm.Open(nil, nonce, cipherText, c.capiAuthData)
	if err != nil {
		c.log.Sugar().Error(err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	c.log.Sugar().With("authType", "capi").Info("valid")
	span.AddEvent("capi is valid")
	return true
}

func (c *CapiValidator) ValidatedIdentity() (identityHeaders []*corev3.HeaderValueOption) {
	capiPayload := strings.Split(string(c.rawIdentityData), ":")

	if len(capiPayload) < 2 {
		c.log.Sugar().Errorf("bad capi token payload format, len: %d", len(capiPayload))
		return nil
	}

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "CAPI-EMAIL",
			Value: capiPayload[0],
		},
	})

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "CAPI-SIGNATURE",
			Value: capiPayload[1],
		},
	})
	return

}
