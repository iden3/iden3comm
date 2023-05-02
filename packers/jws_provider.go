package packers

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	bjj "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const BJJAlg jwa.SignatureAlgorithm = "BJJ"

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

type BjjProvider struct{}

func (b *BjjProvider) Algorithm() jwa.SignatureAlgorithm {
	return BJJAlg
}

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

	fmt.Println("sig digest:", digest)

	return sig[:], nil
}

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
	if err := poseidonComSig.UnmarshalText(signature); err != nil {
		return fmt.Errorf("can't unmarshal bjj signature: %v", err)
	}
	poseidonDecSig, err := poseidonComSig.Decompress()
	if err != nil {
		return fmt.Errorf("can't decompress bjj signature: %v", err)
	}

	fmt.Println("verify digest:", digest)
	fmt.Println("verify poseidonComSig:", hex.EncodeToString(poseidonComSig[:]))

	if !bjjPubKey.VerifyPoseidon(digest, poseidonDecSig) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
