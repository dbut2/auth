package providers

import (
	"context"

	"github.com/huandu/facebook"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

type facebookConfig struct {
	BaseConfig `yaml:",inline"`
}

func (f facebookConfig) Build(name string, redirectBase string) (Provider, error) {
	return f.BaseConfig.BuildWith(name, redirectBase, endpoints.Facebook, f.facebookIdentity())
}

func (f facebookConfig) facebookIdentity() IdentityFunc {
	client := facebook.New(f.ClientID, f.ClientSecret)
	client.EnableAppsecretProof = true
	return func(ctx context.Context, token *oauth2.Token) (any, error) {
		session := client.Session(token.AccessToken)
		session.AppsecretProof()
		return session.User()
	}
}
