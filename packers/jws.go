package packers

import (
	"encoding/json"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

// MediaTypeSignedMessage is media type for jws
const MediaTypeSignedMessage iden3comm.MediaType = "application/iden3-signed-json"

// DIDResolverHandlerFunc resolves did
type DIDResolverHandlerFunc func(did string) (verifiable.DIDDocument, error)

// Resolve function is responsible to call provided handler for resolve did document
func (f DIDResolverHandlerFunc) Resolve(did string) (verifiable.DIDDocument, error) {
	return f(did)
}

// JWSPacker is packer that use jws
type JWSPacker struct {
	didResolverHandler DIDResolverHandlerFunc
	keyResolverHandler KeyResolverHandlerFunc
}

// SigningParams packer parameters for jws generation
type SigningParams struct {
	SenderDID string
	Alg       jose.SignatureAlgorithm
	iden3comm.PackerParams
}

// NewSigningParams defines the signing parameters for jws generation
func NewSigningParams() SigningParams {
	return SigningParams{}
}

// NewJWSPacker creates new jws packer instance
func NewJWSPacker(didResolverHandler DIDResolverHandlerFunc, keyResolverHandlerFunc KeyResolverHandlerFunc) *JWSPacker {
	return &JWSPacker{didResolverHandler, keyResolverHandlerFunc}
}

// Pack returns packed message to transport envelope with a zero knowledge proof in JWS full serialized format
func (p *JWSPacker) Pack(payload []byte, params iden3comm.PackerParams) ([]byte, error) {

	// create hash of message
	var err error
	var token *jose.JSONWebSignature

	signingParams, ok := params.(SigningParams)
	if !ok {
		return nil, errors.New("can't cast params to signer packer params")
	}

	bm := &iden3comm.BasicMessage{}
	err = json.Unmarshal(payload, &bm)
	if err != nil {
		return nil, errors.New("msg singer must me be msg sender")
	}

	if bm.From != signingParams.SenderDID {
		return nil, errors.New("msg singer must me be msg sender")
	}

	// 1. resolver did doc

	_, err = p.didResolverHandler.Resolve(signingParams.SenderDID)

	if err != nil {
		return nil, errors.New("can't resolve did")
	}

	// 2. parse verification method

	const kid = ""

	key, err := p.keyResolverHandler.Resolve(kid)
	if err != nil {
		return nil, errors.New("can't resolve key")
	}
	// 3. sign with ...

	// This time, sign and do not embed JWK in message
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		return nil, errors.New("can't create signer")
	}

	token, err = signer.Sign(payload)
	if err != nil {
		return nil, errors.New("can't sign")

	}
	return []byte(token.FullSerialize()), err
}

// Unpack returns unpacked message from transport envelope with verification of signature
func (p *JWSPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {

	token, err := jose.ParseSigned(string(envelope))
	if err != nil {
		return nil, err
	}

	var msg iden3comm.BasicMessage
	err = json.Unmarshal(token.UnsafePayloadWithoutVerification(), &msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &msg, err
}

// MediaType for iden3comm that returns MediaTypeSignedMessage
func (p *JWSPacker) MediaType() iden3comm.MediaType {
	return MediaTypeSignedMessage
}
