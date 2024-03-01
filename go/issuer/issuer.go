package issuer

import (
	"context"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/dbut2/auth/go/crypto"
)

type Issuer interface {
	Issue(ctx context.Context, subject string) (string, error)
	Verify(ctx context.Context, token string) (*jwt.Token, error)
}

type DefaultIssuer struct {
	issuer string
	signer crypto.Signer
}

var _ Issuer = new(DefaultIssuer)

func NewDefaultIssuer(issuer string, signer crypto.Signer) *DefaultIssuer {
	return &DefaultIssuer{
		issuer: issuer,
		signer: signer,
	}
}

func (i *DefaultIssuer) Issue(ctx context.Context, subject string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS512)

	_, kid, err := i.signer.PublicKey(ctx)
	if err != nil {
		return "", err
	}

	token.Header["kid"] = kid
	token.Claims = jwt.StandardClaims{
		ExpiresAt: time.Now().Add(720 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    i.issuer,
		NotBefore: time.Now().Unix(),
		Subject:   subject,
	}

	unsignedToken, err := token.SigningString()
	if err != nil {
		return "", err
	}

	signature, err := i.signer.SignWith(ctx, kid, []byte(unsignedToken))
	if err != nil {
		return "", err
	}

	signedToken := unsignedToken + "." + jwt.EncodeSegment(signature)

	return signedToken, nil
}

func (i *DefaultIssuer) Verify(ctx context.Context, token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		jwks, err := fetchJwks(ctx, token)
		if err != nil {
			return nil, err
		}

		kid := token.Header["kid"].(string)
		key, ok := jwks.LookupKeyID(kid)
		if !ok {
			return nil, errors.New("kid not found in jwks")
		}

		pk := &rsa.PublicKey{}
		err = key.Raw(pk)
		if err != nil {
			return nil, err
		}

		return pk, nil
	})
}

func fetchJwks(ctx context.Context, token *jwt.Token) (jwk.Set, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("not map claims")
	}

	issuer := claims["iss"].(string)
	u := issuer + "/.well-known/jwks.json"
	return jwk.Fetch(ctx, u)
}
