package providers

import (
	"context"

	"github.com/huandu/facebook"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

func init() {
	registerProviderBuilder("facebook", facebookBuilder)
}

var facebookBuilder = ProviderBuilder{
	Endpoint:        endpoints.Facebook,
	IdentityBuilder: facebookIdentity,
}

func facebookIdentity(config ProviderConfig) Identity {
	client := facebook.New(config.ClientID, config.ClientSecret)
	client.EnableAppsecretProof = true
	return func(ctx context.Context, token *oauth2.Token) (any, error) {
		session := client.Session(token.AccessToken)
		session.AppsecretProof()
		return session.User()
	}
}
