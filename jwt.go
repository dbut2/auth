package main

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	issuer = "https://auth.dylanbutler.dev"
)

func Issue(ctx context.Context, signer Signer, id string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS512)

	token.Claims = jwt.StandardClaims{
		ExpiresAt: time.Now().Add(720 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    issuer,
		NotBefore: time.Now().Unix(),
		Subject:   id,
	}

	unsignedToken, err := token.SigningString()
	if err != nil {
		return "", err
	}

	signature, err := signer.Sign(ctx, []byte(unsignedToken))
	if err != nil {
		return "", err
	}

	signedToken := unsignedToken + "." + jwt.EncodeSegment(signature)

	return signedToken, nil
}
