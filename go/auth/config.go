package auth

import (
	"context"

	"github.com/dbut2/auth/go/cookie"
	"github.com/dbut2/auth/go/crypto"
	"github.com/dbut2/auth/go/issuer"
	"github.com/dbut2/auth/go/providers"
	"github.com/dbut2/auth/go/store"
)

type Config struct {
	Address   string               `yaml:"address"`
	Postgres  store.PostgresConfig `yaml:"postgres"`
	Crypto    crypto.Config        `yaml:"crypto"`
	Providers providers.Config     `yaml:"providers"`
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

	issuer := issuer.NewDefaultIssuer(config.Address, signer)

	cookies := cookie.NewDefaultCookies(issuer)

	jwks, err := crypto.GenerateJwks(ctx, signer)
	if err != nil {
		return nil, err
	}

	as := &AuthService{
		address:   config.Address,
		providers: providers,
		signer:    signer,
		encrypter: encrypter,
		issuer:    issuer,
		store:     store,
		cookies:   cookies,
		jwks:      jwks,
	}
	return as, nil
}
