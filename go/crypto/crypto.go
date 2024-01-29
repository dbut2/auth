package crypto

import (
	"context"
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
