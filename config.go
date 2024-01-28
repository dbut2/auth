package main

import (
	"context"
	"os"

	gsm "cloud.google.com/go/secretmanager/apiv1"
	gsmpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"

	"github.com/dbut2/auth/auth"
	"github.com/dbut2/auth/cookie"
	"github.com/dbut2/auth/crypto"
	"github.com/dbut2/auth/providers"
)

type Config struct {
	Address   string           `yaml:"address"`
	Postgres  PostgresConfig   `yaml:"postgres"`
	Keys      crypto.KMSConfig `yaml:"keys"`
	Signer    SignerConfig     `yaml:"signer"`
	Providers ProvidersConfig  `yaml:"providers"`
}

type PostgresConfig struct {
	DSN string `yaml:"dsn"`
}

type SignerConfig struct {
	Secret string `yaml:"keySecret"`
}

func ConfigFromSecret(ctx context.Context, secret string) (Config, error) {
	client, err := gsm.NewClient(ctx)
	if err != nil {
		return Config{}, err
	}

	resp, err := client.AccessSecretVersion(ctx, &gsmpb.AccessSecretVersionRequest{
		Name: secret,
	})
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = yaml.Unmarshal(resp.GetPayload().GetData(), &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func ConfigFromFile(filename string) (Config, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func NewService(ctx context.Context, config Config) (*AuthService, error) {
	providers := NewProviders(config.Providers, config.Address+"/redirect")

	encrypter, err := crypto.NewKMSClient(context.Background(), config.Keys)
	if err != nil {
		return nil, err
	}

	pk, err := crypto.LoadGSMKey(ctx, config.Signer.Secret)
	if err != nil {
		return nil, err
	}
	signer := crypto.NewLocalSigner(pk)

	postgres, err := NewPostgres(config.Postgres)
	if err != nil {
		return nil, err
	}

	store := NewSqlStore(postgres, encrypter)

	issuer := auth.NewDefaultIssuer(config.Address, signer)

	cookies := cookie.NewDefaultCookies(issuer)

	as := &AuthService{
		address:   config.Address,
		providers: providers,
		signer:    signer,
		encrypter: encrypter,
		store:     store,
		cookies:   cookies,
	}
	return as, nil
}

var endpointMap = map[string]oauth2.Endpoint{
	"facebook": facebook.Endpoint,
	"github":   github.Endpoint,
	"google":   google.Endpoint,
}

var identityMap = map[string]providers.IdentityProvider{
	"facebook": nil, // requires post setup
	"github":   providers.GitHubIdentity,
	"google":   providers.GoogleIdentity,
}

func NewProviders(config ProvidersConfig, redirectBase string) Providers {
	p := Providers{}

	for name, pc := range config {
		p[name] = Provider{
			name: name,
			oauth2: &oauth2.Config{
				ClientID:     pc.ClientID,
				ClientSecret: pc.ClientSecret,
				Endpoint:     endpointMap[name],
				RedirectURL:  redirectBase + "/" + name,
				Scopes:       pc.Scopes,
			},
			identity: identityMap[name],
		}
	}

	pFacebook := p["facebook"]
	pFacebook.identity = providers.GetFacebookIdentity(pFacebook.oauth2.ClientID, pFacebook.oauth2.ClientSecret)
	p["facebook"] = pFacebook

	return p
}

type ProvidersConfig = map[string]ProviderConfig

type ProviderConfig struct {
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	Scopes       []string `yaml:"scopes"`
}
