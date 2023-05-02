package packers

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"

	bjj "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// BJJAlg signature algorithm
const BJJAlg jwa.SignatureAlgorithm = "BJJ"

//nolint:gochecknoinits // Need to register BJJAlg
func init() {
	bjjp := &BjjProvider{}
	jws.RegisterSigner(
		bjjp.Algorithm(),
		jws.SignerFactoryFn(
			func() (jws.Signer, error) {
				return bjjp, nil
			},
		))
	jws.RegisterVerifier(
		bjjp.Algorithm(),
		jws.VerifierFactoryFn(
			func() (jws.Verifier, error) {
				return bjjp, nil
			}),
	)
}

// BjjProvider is a signer and verifier for BJJAlg
type BjjProvider struct{}

// Algorithm returns BJJAlg
func (b *BjjProvider) Algorithm() jwa.SignatureAlgorithm {
	return BJJAlg
}

// Sign signs payload with BJJ private key
func (b *BjjProvider) Sign(payload []byte, opts interface{}) ([]byte, error) {
	signer, ok := opts.(crypto.Signer)
	if !ok {
		return nil, errors.New("bjj signer opts support only signer interface")
	}

	digest, err := poseidon.HashBytes(payload)
	if err != nil {
		return nil, fmt.Errorf("failed get poseidon hash for payload: %v", err)
	}

	sig, err := signer.Sign(rand.Reader, digest.Bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %v", err)
	}

	return sig, nil
}

// Verify verifies signature with BJJ public key
func (b *BjjProvider) Verify(payload, signature []byte, opts interface{}) error {
	var bjjPubKey *bjj.PublicKey
	// we can expande opts here
	switch v := opts.(type) {
	case *bjj.PublicKey:
		bjjPubKey = v
	case bjj.PublicKey:
		bjjPubKey = &v
	default:
		return errors.New("provide bjj public key for verification signature")
	}

	digest, err := poseidon.HashBytes(payload)
	if err != nil {
		return fmt.Errorf("failed get poseidon hash for payload: %v", err)
	}
	poseidonComSig := &bjj.SignatureComp{}
	if err = poseidonComSig.UnmarshalText(signature); err != nil {
		return fmt.Errorf("can't unmarshal bjj signature: %v", err)
	}
	poseidonDecSig, err := poseidonComSig.Decompress()
	if err != nil {
		return fmt.Errorf("can't decompress bjj signature: %v", err)
	}

	if !bjjPubKey.VerifyPoseidon(digest, poseidonDecSig) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
