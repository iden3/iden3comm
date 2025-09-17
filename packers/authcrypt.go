package packers

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/iden3/iden3comm/v2/utils"
	joseprimitives "github.com/iden3/jose-primitives"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

//nolint:gochecknoinits // init is needed to register custom algorithm
func init() {
	jwa.RegisterKeyEncryptionAlgorithm(
		jwa.NewKeyEncryptionAlgorithm(
			string(protocol.AuthcryptECDH1PUA256KW)))
}

// MediaTypeAuthEncryptedMessage is media type for auth encrypted message
const MediaTypeAuthEncryptedMessage iden3comm.MediaType = "application/iden3comm-auth-encrypted-json"

// AuthcryptPacker is  packer for auth encryption / decryption
type AuthcryptPacker struct {
	pubKeyResolver  KeyResolverHandlerFunc
	privKeyResolver KeyResolverHandlerFunc
}

// NewAuthcryptPacker returns new auth packers
// Param pubKeyResolver is used to resolve public keys by key id
// Param privKeyResolver is used to resolve private keys by key id
func NewAuthcryptPacker(pubKeyResolver, privKeyResolver KeyResolverHandlerFunc) *AuthcryptPacker {
	return &AuthcryptPacker{pubKeyResolver, privKeyResolver}
}

// AuthcryptPackerParams is params for authcrypt packer
type AuthcryptPackerParams struct {
	SenderKeyID    string
	RecipientKeyID string
	iden3comm.PackerParams
}

func getEcdhPrivateKey(key interface{}) (*ecdh.PrivateKey, error) {
	var senderPrivateKey *ecdh.PrivateKey
	switch sk := key.(type) {
	case *ecdh.PrivateKey:
		senderPrivateKey = sk
	case ecdh.PrivateKey:
		senderPrivateKey = &sk
	default:
		return nil, errors.New("key is not ecdh private key")
	}
	return senderPrivateKey, nil
}

func (p *AuthcryptPacker) resolveJWKByKID(keyID string) (*joseprimitives.JWK, error) {
	k, err := p.pubKeyResolver.Resolve(keyID)
	if err != nil {
		return nil, fmt.Errorf("can't resolve JWK by key")
	}
	var jwk *joseprimitives.JWK
	switch rk := k.(type) {
	case *joseprimitives.JWK:
		jwk = rk
	case joseprimitives.JWK:
		jwk = &rk
	default:
		return nil, fmt.Errorf("key is not *joseprimitives.JWK")
	}
	return jwk, nil
}

func (p *AuthcryptPacker) findPublicKey(keyID string) (*ecdh.PublicKey, error) {
	jwk, err := p.resolveJWKByKID(keyID)
	if err != nil {
		return nil, fmt.Errorf("can't resolve JWK by key id: %w", err)
	}
	publicKey, err := joseprimitives.Export(jwk)
	if err != nil {
		return nil, fmt.Errorf("can't export public key from JWK: %w", err)
	}
	return publicKey, nil
}

// Pack returns packed message to transport envelope
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
func (p *AuthcryptPacker) Pack(payload []byte, params iden3comm.PackerParams) ([]byte, error) {
	packerParams, ok := params.(AuthcryptPackerParams)
	if !ok {
		return nil, errors.New("can't cast params to authcrypt packer params")
	}

	senderKey, err := p.privKeyResolver.Resolve(packerParams.SenderKeyID)
	if err != nil {
		return nil, fmt.Errorf("can't resolve sender key '%s': %w", packerParams.SenderKeyID, err)
	}
	senderPrivateKey, err := getEcdhPrivateKey(senderKey)
	if err != nil {
		return nil, fmt.Errorf("can't get sender private key: %w", err)
	}

	recipientPublicKey, err := p.findPublicKey(packerParams.RecipientKeyID)
	if err != nil {
		return nil, fmt.Errorf("can't find recipient public key '%s': %w", packerParams.RecipientKeyID, err)
	}

	token, err := joseprimitives.Encrypt(
		recipientPublicKey,
		senderPrivateKey,
		payload,
		joseprimitives.WithKidHeader(packerParams.RecipientKeyID),
		joseprimitives.WithSkidHeader(packerParams.SenderKeyID),
		joseprimitives.WithTypeHeader(string(p.MediaType())),
	)
	if err != nil {
		return nil, fmt.Errorf("can't auth encrypt payload: %w", err)
	}

	return []byte(token), nil
}

// Unpack returns unpacked message from transport envelope
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
func (p *AuthcryptPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {
	jweToken, err := jwe.Parse(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwe token: %w", err)
	}

	recipientKeyID, ok := jweToken.ProtectedHeaders().KeyID()
	if !ok || recipientKeyID == "" {
		return nil, errors.New("recipient key id (kid) is missing in the header")
	}
	recipientPrivateKey, err := p.privKeyResolver.Resolve(recipientKeyID)
	if err != nil {
		return nil, fmt.Errorf("can't resolve recipient key '%s': %w", recipientKeyID, err)
	}
	recipientPrivateKeyEcdh, err := getEcdhPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("can't get recipient private key: %w", err)
	}

	var senderKeyID string
	err = jweToken.ProtectedHeaders().Get("skid", &senderKeyID)
	if err != nil {
		return nil, errors.New("sender key id (skid) is missing in the header")
	}
	senderPublicKey, err := p.findPublicKey(senderKeyID)
	if err != nil {
		return nil, fmt.Errorf("can't find sender public key '%s': %w", senderKeyID, err)
	}

	originMessage, err := joseprimitives.Decrypt(recipientPrivateKeyEcdh, senderPublicKey, string(envelope))
	if err != nil {
		return nil, fmt.Errorf("can't decrypt authcrypted message: %w", err)
	}

	var bm iden3comm.BasicMessage
	err = json.Unmarshal(originMessage, &bm)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal basic message: %w", err)
	}

	return &bm, nil
}

// MediaType for iden3comm
func (p *AuthcryptPacker) MediaType() iden3comm.MediaType {
	return MediaTypeAuthEncryptedMessage
}

// GetSupportedProfiles returns supported profiles by packer
func (p *AuthcryptPacker) GetSupportedProfiles() []string {
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
func (p *AuthcryptPacker) IsProfileSupported(profile string) bool {
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

	if len(parsedProfile.AcceptCircuits) > 0 ||
		len(parsedProfile.AcceptAnoncryptAlgorithms) > 0 ||
		len(parsedProfile.AcceptJwzAlgorithms) > 0 ||
		len(parsedProfile.AcceptJwsAlgorithms) > 0 {
		return false
	}

	if len(parsedProfile.AcceptAuthcryptAlgorithms) == 0 {
		return true
	}

	supportedAlgorithms := p.getSupportedAlgorithms()
	for _, alg := range parsedProfile.AcceptAuthcryptAlgorithms {
		for _, supportedAlg := range supportedAlgorithms {
			if string(alg) == supportedAlg {
				return true
			}
		}
	}
	return false
}

func (p *AuthcryptPacker) getSupportedAlgorithms() []string {
	return []string{string(protocol.AuthcryptECDH1PUA256KW)}
}
