package main

import (
	"context"
	"crypto/sha512"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

type KMSClient struct {
	client *kms.KeyManagementClient

	signingKey, encryptingKey, decryptingKey string
}

func NewKMSClient(ctx context.Context, config KeysConfig) (*KMSClient, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	return &KMSClient{
		client:        client,
		signingKey:    config.SigningKey,
		encryptingKey: config.EncryptingKey,
		decryptingKey: config.DecryptingKey,
	}, nil
}

func (k *KMSClient) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hash := sha512.Sum512(data)
	resp, err := k.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: k.signingKey,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: hash[:],
			},
		},
	})
	return resp.GetSignature(), err
}

func (k *KMSClient) PublicKey(ctx context.Context) ([]byte, error) {
	resp, err := k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: k.signingKey})
	return []byte(resp.GetPem()), err
}

func (k *KMSClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	resp, err := k.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      k.encryptingKey,
		Plaintext: plaintext,
		//PlaintextCrc32C: &wrapperspb.Int64Value{Value: int64(crc32.ChecksumIEEE(plaintext))},
	})
	return resp.GetCiphertext(), err
}

func (k *KMSClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	resp, err := k.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       k.decryptingKey,
		Ciphertext: ciphertext,
		//CiphertextCrc32C: &wrapperspb.Int64Value{Value: int64(crc32.ChecksumIEEE(ciphertext))},
	})
	return resp.GetPlaintext(), err
}
