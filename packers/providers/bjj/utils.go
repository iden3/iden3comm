package bjj

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	bjj "github.com/iden3/go-iden3-crypto/v2/babyjub"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ParseKey parses jwk key to bjj public key
func ParseKey(jwkKey jwk.Key) (*bjj.PublicKey, error) {
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

	bjjPoint := bjj.Point{
		X: big.NewInt(0).SetBytes(x),
		Y: big.NewInt(0).SetBytes(y),
	}
	if !bjjPoint.InCurve() {
		return nil, errors.New("point is not in curve")
	}
	pubKey := bjj.PublicKey(bjjPoint)

	return &pubKey, nil
}

// GoSigner implements crypto.Signer interface
type GoSigner struct {
	pk *bjj.PrivateKey
}

// Public returns nil because we don't need it
func (s *GoSigner) Public() crypto.PublicKey {
	return nil
}

// Sign signs the digest with the private key
func (s *GoSigner) Sign(_ io.Reader, buf []byte, _ crypto.SignerOpts) ([]byte, error) {
	digest := big.NewInt(0).SetBytes(buf)
	signature, err := s.pk.SignPoseidon(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %v", err)
	}

	sig, err := signature.Compress().MarshalText()
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// GoSignerFromPrivHex creates GoSigner from hex encoded private key
func GoSignerFromPrivHex(h string) (*GoSigner, error) {
	rawPK, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(rawPK) != 32 {
		return nil, errors.New("invalid private key length")
	}

	var pk bjj.PrivateKey
	copy(pk[:], rawPK)

	return &GoSigner{&pk}, nil
}
