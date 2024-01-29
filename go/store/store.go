package store

import (
	"context"
	"database/sql"

	"github.com/lib/pq"
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

func NewPostgres(config PostgresConfig) (*sql.DB, error) {
	conn, err := pq.NewConnector(config.DSN)
	if err != nil {
		return nil, err
	}

	return sql.OpenDB(conn), nil
}

type PostgresConfig struct {
	DSN string `yaml:"dsn"`
}
