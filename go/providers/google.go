package providers

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

type googleConfig struct {
	BaseConfig `yaml:",inline"`
}

func (g googleConfig) Name() string { return "google" }

func (g googleConfig) Build(name string, redirectBase string) (Provider, error) {
	return g.BaseConfig.BuildWith(name, redirectBase, endpoints.Google, g.googleIdentity())
}

func (g googleConfig) googleIdentity() IdentityFunc {
	return func(ctx context.Context, token *oauth2.Token) (any, error) {
		httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
		client, err := people.NewService(ctx, option.WithHTTPClient(httpClient))
		if err != nil {
			return nil, err
		}
		person, err := client.People.Get("people/me").PersonFields("names").Do()
		if err != nil {
			return nil, err
		}
		return person.ResourceName, nil
	}
}
