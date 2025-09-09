// Package packers defines core 3 protocol packers: anoncrypt, plain and zkp
package packers

import (
	"encoding/json"
	"fmt"

	"github.com/iden3/iden3comm/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
)

// MediaTypeEncryptedMessage is media type for ecnrypted message
const MediaTypeEncryptedMessage iden3comm.MediaType = "application/iden3comm-encrypted-json"

// AnoncryptPacker is  packer for anon encryption / decryption
type AnoncryptPacker struct {
	kr KeyResolverHandlerFunc
}

// AnoncryptPackerParams is params for anoncrypt packer
type AnoncryptPackerParams struct {
	RecipientKey jwk.Key
	iden3comm.PackerParams
}

// NewAnoncryptPacker returns new anon packers
func NewAnoncryptPacker(kr KeyResolverHandlerFunc) *AnoncryptPacker {
	return &AnoncryptPacker{kr: kr}
}

// KeyResolverHandlerFunc resolve private key by key id
type KeyResolverHandlerFunc func(keyID string) (key interface{}, err error)

// Resolve function is responsible to call provided handler for recipient private key resolve
func (kr KeyResolverHandlerFunc) Resolve(keyID string) (key interface{}, err error) {
	return kr(keyID)
}

// Pack returns packed message to transport envelope
func (p *AnoncryptPacker) Pack(payload []byte, params iden3comm.PackerParams) ([]byte, error) {

	packerParams, ok := params.(AnoncryptPackerParams)
	if !ok {
		return nil, errors.New("can't cast params to anoncrypt packer params")
	}

	kid, ok := packerParams.RecipientKey.KeyID()
	if !ok || kid == "" {
		return nil, errors.New("missing key id in recipient key")
	}

	headers := jwe.NewHeaders()
	headers.Set(jwe.AlgorithmKey, jwa.ECDH_ES_A256KW().String())
	headers.Set(jwe.ContentEncryptionKey, jwa.A256CBC_HS512().String())
	headers.Set(jwe.KeyIDKey, kid)
	headers.Set(jwe.TypeKey, string(p.MediaType()))

	jweString, err := jwe.Encrypt(payload,
		jwe.WithCompact(),
		jwe.WithKey(jwa.ECDH_ES_A256KW(), packerParams.RecipientKey),
		jwe.WithContentEncryption(jwa.A256CBC_HS512()),
		jwe.WithProtectedHeaders(headers),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt message")
	}

	return []byte(jweString), nil
}

// Unpack returns unpacked message from transport envelope
func (p *AnoncryptPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {
	jweMessage, err := jwe.Parse(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwe toekn: %w", err)
	}
	recipientKeyID, ok := jweMessage.ProtectedHeaders().KeyID()
	if !ok || recipientKeyID == "" {
		return nil, errors.New("missing key id in jwe header")
	}
	decryptionKey, err := p.kr.Resolve(recipientKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve recipient key: %w", err)
	}

	payload, err := jwe.Decrypt(envelope, jwe.WithKey(jwa.ECDH_ES_A256KW(), decryptionKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt jwe token: %w", err)
	}

	var msg iden3comm.BasicMessage
	err = json.Unmarshal(payload, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, err
}

// MediaType for iden3comm
func (p *AnoncryptPacker) MediaType() iden3comm.MediaType {
	return MediaTypeEncryptedMessage
}
