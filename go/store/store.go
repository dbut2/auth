package store

import (
	"context"
	"errors"
	"net"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/dbut2/auth/go/models"
)

type Store interface {
	GetUser(ctx context.Context, provider string, identity any) (*models.User, error)
	CreateUser(ctx context.Context) (*models.User, error)

	GetToken(ctx context.Context, provider string, identity any) (*oauth2.Token, error)
	StoreToken(ctx context.Context, user *models.User, provider string, identity any, token *oauth2.Token) error

	GetCodeUser(ctx context.Context, code string) (*models.User, error)
	StoreCode(ctx context.Context, user *models.User, code string) error
}

var (
	ErrNotFound = errors.New("entity not found")
)

func NewPostgres(ctx context.Context, config PostgresConfig) (*pgx.Conn, error) {
	d, err := cloudsqlconn.NewDialer(ctx, cloudsqlconn.WithDefaultDialOptions(cloudsqlconn.WithPrivateIP()))
	if err != nil {
		return nil, err
	}

	c, err := pgx.ParseConfig(config.DSN)
	if err != nil {
		return nil, err
	}

	c.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(ctx, config.ICN)
	}

	return pgx.Connect(ctx, config.DSN)
}

type PostgresConfig struct {
	DSN string `yaml:"dsn"`
	ICN string `yaml:"icn"`
}
