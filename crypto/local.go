package crypto

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"time"

	gsm "cloud.google.com/go/secretmanager/apiv1"
	gsmpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-jwt/jwt"
)

func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func LoadGSMKey(ctx context.Context, secret string) (*rsa.PrivateKey, error) {
	client, err := gsm.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.AccessSecretVersion(ctx, &gsmpb.AccessSecretVersionRequest{Name: secret})
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(resp.GetPayload().GetData())
	if err != nil {
		return nil, err
	}

	return key, nil
}

type LocalSigner struct {
	key *rsa.PrivateKey
}

var _ Signer = new(LocalSigner)

func NewLocalSigner(key *rsa.PrivateKey) *LocalSigner {
	return &LocalSigner{key: key}
}

func (l *LocalSigner) Sign(ctx context.Context, bytes []byte) ([]byte, string, error) {
	hash := sha512.Sum512(bytes)
	bytes, err := l.key.Sign(rand.Reader, hash[:], crypto.SHA512)
	return bytes, "key", err
}

func (l *LocalSigner) SignWith(ctx context.Context, _ string, bytes []byte) ([]byte, error) {
	hash := sha512.Sum512(bytes)
	return l.key.Sign(rand.Reader, hash[:], crypto.SHA512)
}

func (l *LocalSigner) PublicKey(ctx context.Context) ([]byte, string, error) {
	derPkix, err := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	if err != nil {
		return nil, time.Now().String(), err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}

	return pem.EncodeToMemory(pemBlock), "key", nil
}

type LocalEncrypter struct {
	key *rsa.PrivateKey
}

var _ Encrypter = new(LocalEncrypter)

func NewLocalEncrypter(key *rsa.PrivateKey) *LocalEncrypter {
	return &LocalEncrypter{key: key}
}

func (l *LocalEncrypter) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &l.key.PublicKey, plaintext)
}

func (l *LocalEncrypter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, l.key, ciphertext)
}
