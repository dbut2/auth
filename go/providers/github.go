package providers

import (
	"context"
	"net/http"

	"github.com/google/go-github/v58/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

func init() {
	registerProviderBuilder("github", githubBuilder)
}

var githubBuilder = ProviderBuilder{
	Endpoint:        endpoints.GitHub,
	IdentityBuilder: githubIdentity,
}

func githubIdentity(config ProviderConfig) Identity {
	baseClient := github.NewClient(http.DefaultClient)
	return func(ctx context.Context, token *oauth2.Token) (any, error) {
		client := baseClient.WithAuthToken(token.AccessToken)
		user, _, err := client.Users.Get(ctx, "")
		if err != nil {
			return nil, err
		}
		return user.GetID(), nil
	}
}
