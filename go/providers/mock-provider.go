package providers

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"golang.org/x/oauth2"
)

type mockConfig struct {
	BaseConfig `yaml:",inline"`

	InternalHost string `yaml:"internalHost"` // http://mock-provider:8080
	ExternalHost string `yaml:"externalHost"` // http://localhost:8081
}

func (m mockConfig) Name() string { return "mock-provider" }

func (m mockConfig) Build(name string, redirectBase string) (Provider, error) {
	return m.BaseConfig.BuildWith(name, redirectBase, m.Endpoint(), m.mockIdentity())
}

func (m mockConfig) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  strings.TrimRight(m.ExternalHost, "/") + "/default/authorize",
		TokenURL: strings.TrimRight(m.InternalHost, "/") + "/default/token",
	}
}

func (m mockConfig) mockIdentity() IdentityFunc {
	return func(ctx context.Context, token *oauth2.Token) (any, error) {
		httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
		resp, err := httpClient.Get(strings.TrimRight(m.InternalHost, "/") + "/default/userinfo")
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
