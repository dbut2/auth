package crypto

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GenerateJwks(ctx context.Context, signer Signer) (jwk.Set, error) {
	pem, kid, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, _, err := jwk.DecodePEM(pem)
	if err != nil {
		return nil, err
	}
	key, err := jwk.FromRaw(rsaPublicKey)
	if err != nil {
		return nil, err
	}

	err = key.Set("kid", kid)
	if err != nil {
		return nil, err
	}

	set := jwk.NewSet()
	err = set.AddKey(key)
	if err != nil {
		return nil, err
	}
	return set, nil
}
