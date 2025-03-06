package authcrypt

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

func ExtractECDHFromJWK(jwk jose.JSONWebKey) (*ecdh.PublicKey, error) {
	if !jwk.IsPublic() {
		return nil, fmt.Errorf("invalid key type")
	}

	r, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}
	return ECDSaToECDH(r)
}

func ECDSaToECDH(p *ecdsa.PublicKey) (pub *ecdh.PublicKey, err error) {
	pub, err = p.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}
	return
}

func ECHDToECDSA(p *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), p.Bytes())
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to convert public key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
