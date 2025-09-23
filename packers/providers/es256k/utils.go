package es256k

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
)

// ParseKey parses jwk key to ecdsa public key
func ParseKey(jwkKey jwk.Key) (*ecdsa.PublicKey, error) {
	var x []byte
	err := jwkKey.Get("x", &x)
	if err != nil {
		return nil, fmt.Errorf("can't find x: %w", err)
	}

	var y []byte
	err = jwkKey.Get("y", &y)
	if err != nil {
		return nil, fmt.Errorf("can't find y: %w", err)
	}

	pub := ecdsa.PublicKey{
		Curve: ecc.P256k1(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	if !pub.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("ecdsa public key is not on curve (secp256k1)")
	}

	return &pub, nil
}

// PrivateKeyFromHex creates ecdsa private key from hex encoded private key
func PrivateKeyFromHex(h string) (*ecdsa.PrivateKey, error) {
	D, err := big.NewInt(0).SetString(
		h, 16,
	)
	if !err {
		return nil, errors.Errorf("invalid hex string '%s'", h)
	}
	return &ecdsa.PrivateKey{
		D: D,
		PublicKey: ecdsa.PublicKey{
			Curve: ecc.P256k1(),
		},
	}, nil
}

// NewECDSA creates ecdsa public key from encoded key
func NewECDSA(encodedKey []byte) ecdsa.PublicKey {
	return ecdsa.PublicKey{
		Curve: ecc.P256k1(),
		X:     new(big.Int).SetBytes(encodedKey[:32]),
		Y:     new(big.Int).SetBytes(encodedKey[32:]),
	}
}
