// Package packers defines core 3 protocol packers: anoncrypt, plain and zkp
package packers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/iden3/iden3comm/v2/utils"
	"github.com/pkg/errors"
	"gopkg.in/go-jose/go-jose.v2"
)

// MediaTypeEncryptedMessage is media type for ecnrypted message
const MediaTypeEncryptedMessage iden3comm.MediaType = "application/iden3comm-encrypted-json"

// AnoncryptPacker is  packer for anon encryption / decryption
type AnoncryptPacker struct {
	kr KeyResolverHandlerFunc
}

// AnoncryptPackerParams is params for anoncrypt packer
type AnoncryptPackerParams struct {
	RecipientKey *jose.JSONWebKey
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

	encryptor, err := jose.NewEncrypter(jose.A256CBC_HS512, jose.Recipient{
		Algorithm: jose.ECDH_ES_A256KW,
		Key:       packerParams.RecipientKey,
		KeyID:     packerParams.RecipientKey.KeyID,
	}, new(jose.EncrypterOptions).WithType(jose.ContentType(MediaTypeEncryptedMessage)))
	if err != nil {
		return nil, err
	}
	jwe, err := encryptor.Encrypt(payload)
	if err != nil {
		return nil, err
	}
	jweString, err := jwe.CompactSerialize()
	if err != nil {
		return nil, err
	}
	return []byte(jweString), nil

}

// Unpack returns unpacked message from transport envelope
func (p *AnoncryptPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {

	jwe, err := jose.ParseEncrypted(string(envelope))
	if err != nil {
		return nil, err
	}
	decryptionKey, err := p.kr.Resolve(jwe.Header.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := jwe.Decrypt(decryptionKey)
	if err != nil {
		return nil, err
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

// GetSupportedProfiles gets packer envelope (supported profiles) with options
func (p *AnoncryptPacker) GetSupportedProfiles() []string {
	return []string{
		fmt.Sprintf(
			"%s;env=%s&alg=%s",
			protocol.Iden3CommVersion1,
			p.MediaType(),
			strings.Join(p.getSupportedAlgorithms(), ","),
		),
	}
}

// IsProfileSupported checks if profile is supported by packer
func (p *AnoncryptPacker) IsProfileSupported(profile string) bool {
	parsedProfile, err := utils.ParseAcceptProfile(profile)
	if err != nil {
		return false
	}

	if parsedProfile.AcceptedVersion != protocol.Iden3CommVersion1 {
		return false
	}

	if parsedProfile.Env != p.MediaType() {
		return false
	}

	if len(parsedProfile.AcceptCircuits) > 0 || len(parsedProfile.AcceptJwzAlgorithms) > 0 || len(parsedProfile.AcceptJwsAlgorithms) > 0 {
		return false
	}

	if len(parsedProfile.AcceptAnoncryptAlgorithms) == 0 {
		return true
	}

	supportedAlgorithms := p.getSupportedAlgorithms()
	for _, alg := range parsedProfile.AcceptAnoncryptAlgorithms {
		for _, supportedAlg := range supportedAlgorithms {
			if string(alg) == supportedAlg {
				return true
			}
		}
	}
	return false

}

func (p *AnoncryptPacker) getSupportedAlgorithms() []string {
	return []string{string(jose.ECDH_ES_A256KW)}
}
