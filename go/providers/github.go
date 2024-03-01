package providers

import (
	"context"
	"net/http"

	"github.com/google/go-github/v58/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

type githubConfig struct {
	BaseConfig `yaml:",inline"`
}

func (g githubConfig) Build(name string, redirectBase string) (Provider, error) {
	return g.BaseConfig.BuildWith(name, redirectBase, endpoints.GitHub, g.githubIdentity())
}

func (g githubConfig) githubIdentity() IdentityFunc {
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
