package providers

import (
	"context"
	"strings"

	"golang.org/x/oauth2"
)

func New(c Config, address string) (Providers, error) {
	redirectBase := strings.TrimRight(address, "/") + "/redirect"
	p := Providers{}
	var err error
	for name, pc := range c.Providers {
		p[name], err = pc.Build(name, redirectBase)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

type ProviderConfig interface {
	Name() string
	Build(name string, redirectBase string) (Provider, error)
}

type BaseConfig struct {
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	Scopes       []string `yaml:"scopes"`
}

func (b BaseConfig) BuildWith(name string, redirectBase string, endpoint oauth2.Endpoint, identity IdentityFunc) (Provider, error) {
	return Provider{
		Name: name,
		OAuth2: &oauth2.Config{
			ClientID:     b.ClientID,
			ClientSecret: b.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  strings.TrimRight(redirectBase, "/") + "/" + name,
			Scopes:       b.Scopes,
		},
		Identity: identity,
	}, nil
}

type Providers map[string]Provider

type Provider struct {
	Name     string
	OAuth2   *oauth2.Config
	Identity IdentityFunc
}

type IdentityFunc func(ctx context.Context, token *oauth2.Token) (any, error)
