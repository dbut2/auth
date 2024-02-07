package crypto

import (
	"context"
	"crypto/sha512"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

type KMSSigner struct {
	client *kms.KeyManagementClient

	signingKey string
}

var _ Signer = new(KMSSigner)

func NewKMSSigner(client *kms.KeyManagementClient, signingKey string) *KMSSigner {
	return &KMSSigner{client: client, signingKey: signingKey}
}

func (k *KMSSigner) Sign(ctx context.Context, data []byte) ([]byte, string, error) {
	hash := sha512.Sum512(data)
	resp, err := k.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: k.signingKey,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: hash[:],
			},
		},
	})
	return resp.GetSignature(), "key", err
}

func (k *KMSSigner) SignWith(ctx context.Context, _ string, data []byte) ([]byte, error) {
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

func (k *KMSSigner) PublicKey(ctx context.Context) ([]byte, string, error) {
	resp, err := k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: k.signingKey})
	return []byte(resp.GetPem()), "key", err
}

type KMSEncrypter struct {
	client *kms.KeyManagementClient

	encryptingKey, decryptingKey string
}

var _ Encrypter = new(KMSEncrypter)

func NewKMSEncrypter(client *kms.KeyManagementClient, encryptingKey, decryptingKey string) *KMSEncrypter {
	return &KMSEncrypter{client: client, encryptingKey: encryptingKey, decryptingKey: decryptingKey}
}

func (k *KMSEncrypter) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	resp, err := k.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      k.encryptingKey,
		Plaintext: plaintext,
		//PlaintextCrc32C: &wrapperspb.Int64Value{Value: int64(crc32.ChecksumIEEE(plaintext))},
	})
	return resp.GetCiphertext(), err
}

func (k *KMSEncrypter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	resp, err := k.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       k.decryptingKey,
		Ciphertext: ciphertext,
		//CiphertextCrc32C: &wrapperspb.Int64Value{Value: int64(crc32.ChecksumIEEE(ciphertext))},
	})
	return resp.GetPlaintext(), err
}
