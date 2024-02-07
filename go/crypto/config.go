package crypto

import (
	"context"
	"crypto/rsa"

	kms "cloud.google.com/go/kms/apiv1"
)

type Config struct {
	Signer    SignerConfig    `yaml:"signer"`
	Encrypter EncrypterConfig `yaml:"encrypter"`
}

type SignerConfig struct {
	Local      bool   `yaml:"local"`
	Generate   bool   `yaml:"generate"`
	KeySecret  string `yaml:"keySecret"`
	SigningKey string `yaml:"signingKey"`
}

type EncrypterConfig struct {
	Local         bool   `yaml:"local"`
	EncryptingKey string `yaml:"encryptingKey"`
	DecryptingKey string `yaml:"decryptingKey"`
}

func New(ctx context.Context, c Config) (Signer, Encrypter, error) {
	signer, err := NewSigner(ctx, c.Signer)
	if err != nil {
		return nil, nil, err
	}

	encrypter, err := NewEncrypter(ctx, c.Encrypter)
	if err != nil {
		return nil, nil, err
	}

	return signer, encrypter, nil
}

func NewSigner(ctx context.Context, c SignerConfig) (Signer, error) {
	if c.Local {
		return newLocalSigner(ctx, c)
	}

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	return NewKMSSigner(kmsClient, c.SigningKey), nil
}

func newLocalSigner(ctx context.Context, c SignerConfig) (Signer, error) {
	var pk *rsa.PrivateKey
	if c.Generate {
		var err error
		pk, err = GenerateKey()
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		pk, err = LoadGSMKey(ctx, c.KeySecret)
		if err != nil {
			return nil, err
		}
	}

	return NewLocalSigner(pk), nil
}

func NewEncrypter(ctx context.Context, c EncrypterConfig) (Encrypter, error) {
	if c.Local {
		return LocalEncrypter{}, nil
	}

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	return NewKMSEncrypter(kmsClient, c.EncryptingKey, c.DecryptingKey), nil
}
