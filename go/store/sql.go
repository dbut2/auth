package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"

	"github.com/dbut2/auth/go/crypto"
	"github.com/dbut2/auth/go/models"
	"github.com/dbut2/auth/go/store/sql"
)

type SqlStore struct {
	queries   *sql.Queries
	encrypter crypto.Encrypter
}

var _ Store = new(SqlStore)

func NewSqlStore(db sql.DBTX, encrypter crypto.Encrypter) *SqlStore {
	return &SqlStore{queries: sql.New(db), encrypter: encrypter}
}

func (p *SqlStore) GetUser(ctx context.Context, provider string, identity any) (*models.User, error) {
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}

	userID, err := p.queries.GetUser(ctx, sql.GetUserParams{
		Provider:         provider,
		Provideridentity: string(identityBytes),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &models.User{ID: int(userID)}, nil
}

func (p *SqlStore) CreateUser(ctx context.Context) (*models.User, error) {
	userID, err := p.queries.CreateUser(ctx)
	if err != nil {
		return nil, err
	}

	return &models.User{ID: int(userID)}, err
}

func (p *SqlStore) GetToken(ctx context.Context, provider string, identity any) (*oauth2.Token, error) {
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}

	encryptedToken, err := p.queries.GetToken(ctx, sql.GetTokenParams{
		Provider:         provider,
		Provideridentity: string(identityBytes),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if !encryptedToken.Valid {
		return nil, nil
	}

	return p.decryptToken(ctx, encryptedToken.String)
}

func (p *SqlStore) encryptToken(ctx context.Context, token *oauth2.Token) (string, error) {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	cipher, err := p.encrypter.Encrypt(ctx, tokenBytes)
	if err != nil {
		return "", err
	}

	encoded := base64.RawStdEncoding.EncodeToString(cipher)
	return encoded, nil
}

func (p *SqlStore) decryptToken(ctx context.Context, cipher string) (*oauth2.Token, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(cipher)
	if err != nil {
		return nil, err
	}

	tokenBytes, err := p.encrypter.Decrypt(ctx, decoded)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{}
	err = json.Unmarshal(tokenBytes, token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (p *SqlStore) StoreToken(ctx context.Context, user *models.User, provider string, identity any, token *oauth2.Token) error {
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	encryptedToken, err := p.encryptToken(ctx, token)
	if err != nil {
		return err
	}

	return p.queries.StoreToken(ctx, sql.StoreTokenParams{
		Provider:         provider,
		Provideridentity: string(identityBytes),
		Userid:           int32(user.ID),
		Token:            pgtype.Text{String: encryptedToken, Valid: true},
	})
}

func (p *SqlStore) GetCodeUser(ctx context.Context, code string) (*models.User, error) {
	userID, err := p.queries.GetCodeUser(ctx, code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &models.User{ID: int(userID)}, nil
}

func (p *SqlStore) StoreCode(ctx context.Context, user *models.User, code string) error {
	return p.queries.StoreCode(ctx, sql.StoreCodeParams{
		Code:   code,
		Userid: int32(user.ID),
	})
}
