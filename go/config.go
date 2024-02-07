package main

import (
	"context"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/dbut2/auth/go/auth"
	"github.com/dbut2/auth/go/cookie"
	"github.com/dbut2/auth/go/crypto"
	"github.com/dbut2/auth/go/providers"
	"github.com/dbut2/auth/go/store"
)

type Config struct {
	Address   string               `yaml:"address"`
	Postgres  store.PostgresConfig `yaml:"postgres"`
	Crypto    crypto.Config        `yaml:"crypto"`
	Providers providers.Config     `yaml:"providers"`
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
	providers, err := providers.New(config.Providers, config.Address)
	if err != nil {
		return nil, err
	}

	postgres, err := store.NewPostgres(ctx, config.Postgres)
	if err != nil {
		return nil, err
	}

	signer, encrypter, err := crypto.New(ctx, config.Crypto)
	if err != nil {
		return nil, err
	}

	store := store.NewSqlStore(postgres, encrypter)

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
