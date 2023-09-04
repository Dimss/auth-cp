package validator

import (
	"github.com/spf13/viper"
)

type Options struct {
	AuthCookie           string
	AuthHeader           string
	InsecureSkipVerify   bool
	JwksServerURLs       []string
	Oauth2TokenIssuer    string
	Oauth2ClaimsValidate []string
	DisableValidators    []string
}

func NewOptionsFromFlags() *Options {
	return &Options{
		AuthCookie:           viper.GetString("auth-cookie"),
		AuthHeader:           viper.GetString("auth-header"),
		InsecureSkipVerify:   viper.GetBool("insecure-skip-verify"),
		JwksServerURLs:       viper.GetStringSlice("jwks-servers"),
		Oauth2ClaimsValidate: viper.GetStringSlice("oauth2-claims-validate"),
		Oauth2TokenIssuer:    viper.GetString("oauth2-token-issuer"),
		DisableValidators:    viper.GetStringSlice("disable-validators"),
	}
}

func (opts *Options) validatorDisabled(validatorType string) bool {
	for _, d := range opts.DisableValidators {
		if d == validatorType {
			return true
		}
	}
	return false
}
