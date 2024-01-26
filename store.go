package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/lib/pq"
	"golang.org/x/oauth2"
)

type Store interface {
	GetUser(ctx context.Context, provider string, identity any) (*User, error)
	CreateUser(ctx context.Context) (*User, error)

	GetToken(ctx context.Context, provider string, identity any) (*oauth2.Token, error)
	StoreToken(ctx context.Context, user *User, provider string, identity any, token *oauth2.Token) error

	GetCodeUser(ctx context.Context, code string) (*User, error)
	StoreCode(ctx context.Context, user *User, code string) error
}

type Postgres struct {
	db        *sql.DB
	encrypter Encrypter
}

var _ Store = new(Postgres)

func NewPostgres(config PostgresConfig, encrypter Encrypter) (*Postgres, error) {
	conn, err := pq.NewConnector(config.DSN)
	if err != nil {
		return nil, err
	}

	return &Postgres{db: sql.OpenDB(conn), encrypter: encrypter}, nil
}

func (p *Postgres) GetUser(ctx context.Context, provider string, identity any) (*User, error) {
	stmt, err := p.db.PrepareContext(ctx, getUserStmt)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}

	row := stmt.QueryRowContext(ctx, provider, identityBytes)
	if row.Err() != nil {
		return nil, err
	}

	user := &User{}
	err = row.Scan(&user.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

const getUserStmt = `
SELECT u.ID FROM Users u

INNER JOIN UserTokens ut on ut.UserID = u.ID

WHERE ut.Provider = $1
AND ut.ProviderIdentity = $2

LIMIT 1;
`

func (p *Postgres) CreateUser(ctx context.Context) (*User, error) {
	tx, err := p.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, createUserStmt)
	if err != nil {
		return nil, err
	}

	row, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	if row.Err() != nil {
		return nil, err
	}

	if !row.Next() {
		return nil, errors.New("query returned no new user")
	}

	user := &User{}
	err = row.Scan(&user.ID)
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return user, nil
}

const createUserStmt = `
INSERT INTO Users DEFAULT VALUES RETURNING ID;
`

func (p *Postgres) GetToken(ctx context.Context, provider string, identity any) (*oauth2.Token, error) {
	stmt, err := p.db.PrepareContext(ctx, getTokenStmt)
	if err != nil {
		return nil, err
	}

	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}

	row := stmt.QueryRowContext(ctx, provider, identityBytes)
	if row.Err() != nil {
		return nil, err
	}

	var tokenBytes []byte
	err = row.Scan(&tokenBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	token, err := p.decryptToken(ctx, string(tokenBytes))
	if err != nil {
		return nil, err
	}
	return token, nil
}

const getTokenStmt = `
SELECT Token FROM UserTokens ut

WHERE ut.Provider = $1
AND ut.ProviderIdentity = $2

LIMIT 1;
`

func (p *Postgres) encryptToken(ctx context.Context, token *oauth2.Token) (string, error) {
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

func (p *Postgres) decryptToken(ctx context.Context, cipher string) (*oauth2.Token, error) {
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

func (p *Postgres) StoreToken(ctx context.Context, user *User, provider string, identity any, token *oauth2.Token) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	tokenBytes, err := p.encryptToken(ctx, token)
	if err != nil {
		return err
	}

	oldToken, err := p.GetToken(ctx, provider, identity)
	if err != nil {
		return err
	}

	if oldToken == nil {
		err = p.createToken(ctx, tx, provider, identityBytes, user.ID, tokenBytes)
	} else {
		err = p.updateToken(ctx, tx, provider, identityBytes, tokenBytes)
	}
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (p *Postgres) createToken(ctx context.Context, tx *sql.Tx, provider string, identityBytes []byte, userID int, token string) error {
	stmt, err := tx.PrepareContext(ctx, createTokenStmt)
	if err != nil {
		return err
	}

	_, err = stmt.ExecContext(ctx, provider, identityBytes, userID, token)
	if err != nil {
		return err
	}

	return nil
}

const createTokenStmt = `
INSERT INTO UserTokens (Provider, ProviderIdentity, UserID, Token) VALUES ($1, $2, $3, $4);
`

func (p *Postgres) updateToken(ctx context.Context, tx *sql.Tx, provider string, identityBytes []byte, token string) error {
	stmt, err := tx.PrepareContext(ctx, updateTokenStmt)
	if err != nil {
		return err
	}

	_, err = stmt.ExecContext(ctx, token, provider, identityBytes)
	if err != nil {
		return err
	}

	return nil
}

const updateTokenStmt = `
UPDATE UserTokens

SET Token = $1

WHERE Provider = $2
AND ProviderIdentity = $3;
`

func (p *Postgres) GetCodeUser(ctx context.Context, code string) (*User, error) {
	stmt, err := p.db.PrepareContext(ctx, getCodeUserStmt)
	if err != nil {
		return nil, err
	}

	row := stmt.QueryRowContext(ctx, code)
	if row.Err() != nil {
		return nil, err
	}

	user := &User{}
	err = row.Scan(&user.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

const getCodeUserStmt = `
SELECT u.ID FROM Users u

INNER JOIN Codes c on c.UserID = u.ID

WHERE c.Code = $1

LIMIT 1;
`

func (p *Postgres) StoreCode(ctx context.Context, user *User, code string) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, storeCodeStmt)
	if err != nil {
		return err
	}

	_, err = stmt.ExecContext(ctx, code, user.ID)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

const storeCodeStmt = `
INSERT INTO Codes (Code, UserID) VALUES ($1, $2);
`
