package providers

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

type Config struct {
	Providers map[string]ProviderConfig `yaml:",inline"`
}

func New(c Config, address string) (Providers, error) {
	redirectBase := strings.TrimRight(address, "/") + "/redirect"

	p := Providers{}
	for name, pc := range c.Providers {
		builder, ok := providerBuilders[name]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		p[name] = builder.Build(name, pc, redirectBase)
	}
	return p, nil
}

var providerBuilders = map[string]ProviderBuilder{}

func registerProviderBuilder(name string, pb ProviderBuilder) {
	providerBuilders[name] = pb
}

type ProviderConfig struct {
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	Scopes       []string `yaml:"scopes"`
}

type ProviderBuilder struct {
	Endpoint        oauth2.Endpoint
	IdentityBuilder IdentityBuilder
}

func (p ProviderBuilder) Build(name string, config ProviderConfig, redirectBase string) Provider {
	return Provider{
		Name: name,
		OAuth2: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     p.Endpoint,
			RedirectURL:  strings.TrimRight(redirectBase, "/") + "/" + name,
			Scopes:       config.Scopes,
		},
		Identity: p.IdentityBuilder(config),
	}
}

type Providers map[string]Provider

type Provider struct {
	Name     string
	OAuth2   *oauth2.Config
	Identity Identity
}

type IdentityBuilder func(config ProviderConfig) Identity

type Identity func(ctx context.Context, token *oauth2.Token) (any, error)
