package providers

import (
	"context"
	"encoding/json"
	"io"

	"golang.org/x/oauth2"
)

func init() {
	registerProviderBuilder("mock-provider", mockBuilder)
}

var mockBuilder = ProviderBuilder{
	Endpoint: oauth2.Endpoint{
		AuthURL:  "http://localhost:8081/default/authorize",
		TokenURL: "http://mock-provider:8080/default/token",
	},
	IdentityBuilder: mockIdentity,
}

func mockIdentity(config ProviderConfig) Identity {
	return func(ctx context.Context, token *oauth2.Token) (any, error) {
		httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
		resp, err := httpClient.Get("http://mock-provider:8080/default/userinfo")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		d := map[string]any{}
		err = json.Unmarshal(bytes, &d)
		if err != nil {
			return nil, err
		}
		return d["sub"], nil
	}
}
