package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"

	gsm "cloud.google.com/go/secretmanager/apiv1"
	gsmpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/dbut2/auth/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
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

	issuer := newDefaultIssuer(config.Address, signer)

	cookies := newDefaultCookies(issuer)

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

func Error(c *gin.Context, err error) {
	c.String(http.StatusInternalServerError, "Something went wrong!")

}

func (a *AuthService) Redirect(c *gin.Context) {
	pp := c.Param("provider")

	code := c.Query("code")
	state := c.Query("state")

	user, err := a.Take(c, pp, code)
	if err != nil {
		c.Error(err)
		Error(c, err)
		return
	}

	code, err = a.GenerateCode(c, user)
	if err != nil {
		c.Error(err)
		Error(c, err)
		return
	}

	if state == "no-state" {
		c.Redirect(http.StatusTemporaryRedirect, a.address)
		return
	}

	u, err := url.Parse(state)
	if err != nil {
		c.Status(http.StatusOK)
		return
	}

	q := u.Query()
	q.Add("code", code)
	u.RawQuery = q.Encode()

	c.Redirect(http.StatusTemporaryRedirect, u.String())
}

// Take will swap a code for a token and return a User, creating one if not exists
func (a *AuthService) Take(ctx context.Context, provider string, code string) (*User, error) {
	p := a.providers[provider]

	token, err := p.oauth2.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	identity, err := p.identity(ctx, token)
	if err != nil {
		return nil, err
	}

	user, err := a.store.GetUser(ctx, provider, identity)
	if err != nil {
		return nil, err
	}

	if user == nil {
		user, err = a.store.CreateUser(ctx)
		if err != nil {
			return nil, err
		}
	}

	err = a.store.StoreToken(ctx, user, provider, identity, token)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (a *AuthService) GenerateCode(ctx context.Context, user *User) (string, error) {
	uid := uuid.New().String()

	err := a.store.StoreCode(ctx, user, uid)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString([]byte(uid)), nil
}

var endpointMap = map[string]oauth2.Endpoint{
	"facebook": facebook.Endpoint,
	"github":   github.Endpoint,
	"google":   google.Endpoint,
}

var identityMap = map[string]IdentityProvider{
	"facebook": nil, // requires post setup
	"github":   GitHubIdentity,
	"google":   GoogleIdentity,
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
	pFacebook.identity = GetFacebookIdentity(pFacebook.oauth2.ClientID, pFacebook.oauth2.ClientSecret)
	p["facebook"] = pFacebook

	return p
}

type ProvidersConfig = map[string]ProviderConfig

type ProviderConfig struct {
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	Scopes       []string `yaml:"scopes"`
}
