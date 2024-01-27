package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
)

type Signer interface {
	Sign(ctx context.Context, data []byte) ([]byte, string, error)
	SignWith(ctx context.Context, kid string, data []byte) ([]byte, error)
	PublicKey(ctx context.Context) ([]byte, string, error)
}

type Encrypter interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type SignerEncrypter interface {
	Signer
	Encrypter
}

type LocalSignerEncrypter struct {
	key *rsa.PrivateKey
}

var _ Signer = new(LocalSignerEncrypter)
var _ Encrypter = new(LocalSignerEncrypter)

func NewLocalSigner() (*LocalSignerEncrypter, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	return &LocalSignerEncrypter{
		key: key,
	}, nil
}

func (l *LocalSignerEncrypter) Sign(ctx context.Context, bytes []byte) ([]byte, string, error) {
	hash := sha512.Sum512(bytes)
	bytes, err := l.key.Sign(rand.Reader, hash[:], crypto.SHA512)
	return bytes, "key", err
}

func (l *LocalSignerEncrypter) SignWith(ctx context.Context, _ string, bytes []byte) ([]byte, error) {
	hash := sha512.Sum512(bytes)
	return l.key.Sign(rand.Reader, hash[:], crypto.SHA512)
}

func (l *LocalSignerEncrypter) PublicKey(ctx context.Context) ([]byte, string, error) {
	derPkix, err := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	if err != nil {
		return nil, "key", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}

	return pem.EncodeToMemory(pemBlock), "key", nil
}

func (l *LocalSignerEncrypter) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &l.key.PublicKey, plaintext)
}

func (l *LocalSignerEncrypter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, l.key, ciphertext)
}
