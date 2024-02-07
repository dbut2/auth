package providers

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

func init() {
	registerProviderBuilder("google", googleBuilder)
}

var googleBuilder = ProviderBuilder{
	Endpoint:        endpoints.Google,
	IdentityBuilder: googleIdentity,
}

func googleIdentity(config ProviderConfig) Identity {
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
