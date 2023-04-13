package packers

import (
	"encoding/json"

	"github.com/iden3/iden3comm"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

// MediaTypeSignedMessage is media type for jws
const MediaTypeSignedMessage iden3comm.MediaType = "application/iden3-signed-json"

// JWSPacker is packer that use jws
type JWSPacker struct {
}

// SigningParams packer parameters for jws generation
type SigningParams struct {
	iden3comm.PackerParams
}

// NewSigningParams defines the signing parameters for jws generation
func NewSigningParams() SigningParams {
	return SigningParams{}
}

// NewJWSPacker creates new jws packer instance
func NewJWSPacker() *JWSPacker {
	return &JWSPacker{}
}

// Pack returns packed message to transport envelope with a zero knowledge proof in JWS full serialized format
func (p *JWSPacker) Pack(payload []byte, params iden3comm.PackerParams) ([]byte, error) {

	// create hash of message
	var err error
	var token *jose.JSONWebSignature

	_, ok := params.(SigningParams)
	if !ok {
		return nil, errors.New("can't cast params to signer packer params")
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
