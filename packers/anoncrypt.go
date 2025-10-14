// Package packers defines core 3 protocol packers: anoncrypt, plain and zkp
package packers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	jweProvider "github.com/iden3/iden3comm/v2/packers/providers/jwe"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/iden3/iden3comm/v2/utils"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
)

var (
	defaultKEA = jwa.RSA_OAEP_256()
	defaultCEA = jwa.A256GCM()
)

// MediaTypeEncryptedMessage is media type for encrypted message
const MediaTypeEncryptedMessage iden3comm.MediaType = "application/iden3comm-encrypted-json"

// AnoncryptPacker is  packer for anon encryption / decryption
type AnoncryptPacker struct {
	didDocumentResolver DidDocumentResolverFunc
	privateKeyResolver  KeyResolverHandlerFunc
}

// AnoncryptRecipients is recipient info for anoncrypt packer
type AnoncryptRecipients struct {
	DID    string
	JWKAlg string
}

// AnoncryptPackerParams is params for anoncrypt packer
type AnoncryptPackerParams struct {
	RecipientKey               jwk.Key
	Recipients                 []AnoncryptRecipients
	ContentEncryptionAlgorithm string
	iden3comm.PackerParams
}

func (p *AnoncryptPackerParams) withDefault() error {
	if len(p.Recipients) == 0 && p.RecipientKey == nil {
		return errors.New("no recipient keys provided")
	}

	if p.ContentEncryptionAlgorithm == "" {
		p.ContentEncryptionAlgorithm = defaultCEA.String()
	} else if !jweProvider.IsSupportedContentEncryptionAlgorithm(p.ContentEncryptionAlgorithm) {
		return errors.New("unsupported content encryption algorithm")
	}

	for i := range p.Recipients {
		if p.Recipients[i].JWKAlg == "" {
			p.Recipients[i].JWKAlg = defaultKEA.String()
		} else if !jweProvider.IsSupportedKeyEncryptionAlgorithm(p.Recipients[i].JWKAlg) {
			return errors.New("unsupported recipient key algorithm")
		}
	}

	if p.RecipientKey != nil {
		alg, ok := p.RecipientKey.Algorithm()
		if !ok || alg == nil {
			return errors.New("missing alg in recipient key")
		}
		if !jweProvider.IsSupportedKeyEncryptionAlgorithm(alg.String()) {
			return errors.New("unsupported recipient key algorithm")
		}
	}

	return nil
}

// NewAnoncryptPacker returns new anon packers
func NewAnoncryptPacker(
	kr KeyResolverHandlerFunc,
	dr DidDocumentResolverFunc,
) *AnoncryptPacker {
	return &AnoncryptPacker{
		privateKeyResolver:  kr,
		didDocumentResolver: dr,
	}
}

// KeyResolverHandlerFunc resolve private key by key id
type KeyResolverHandlerFunc func(keyID string) (key interface{}, err error)

// Resolve function is responsible to call provided handler for recipient private key resolve
func (kr KeyResolverHandlerFunc) Resolve(keyID string) (key interface{}, err error) {
	return kr(keyID)
}

// DidDocumentResolverFunc resolves did document by did
type DidDocumentResolverFunc func(ctx context.Context, did string, opts *services.ResolverOpts) (*document.DidResolution, error)

// Resolve function is responsible to call provided handler for did document resolve
func (d DidDocumentResolverFunc) Resolve(ctx context.Context, did string, opts *services.ResolverOpts) (*document.DidResolution, error) {
	return d(ctx, did, opts)
}

// Pack returns packed message to transport envelope
func (p *AnoncryptPacker) Pack(payload []byte, params iden3comm.PackerParams) ([]byte, error) {
	packerParams, ok := params.(AnoncryptPackerParams)
	if !ok {
		return nil, errors.New("can't cast params to anoncrypt packer params")
	}
	if err := packerParams.withDefault(); err != nil {
		return nil, errors.Wrap(err, "failed to set default values to packer params")
	}

	var recipientsKeys []jwk.Key
	for _, recipient := range packerParams.Recipients {
		recipientDidDocument, err := p.didDocumentResolver.Resolve(context.Background(), recipient.DID, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to resolve did document for did %s", recipient.DID)
		}
		recipientJWK, err := ResolveRecipientKeyFromDIDDoc(recipientDidDocument.DidDocument, recipient.JWKAlg)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to resolve recipient key from did document for did %s", recipient.DID)
		}
		recipientsKeys = append(recipientsKeys, recipientJWK)
	}

	if packerParams.RecipientKey != nil {
		validDirectKey, err := IsValidDirectKey(packerParams.RecipientKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to validate direct recipient key")
		}
		recipientsKeys = append(recipientsKeys, validDirectKey)
	}

	h := jwe.NewHeaders()
	if err := h.Set(jwe.TypeKey, string(p.MediaType())); err != nil {
		return nil, errors.Wrap(err, "failed to set typ header")
	}

	ret, err := jweProvider.Encrypt(
		payload,
		recipientsKeys,
		jweProvider.WithAdditionalProtectedHeaders(h),
		jweProvider.WithContentEncryptionAlgorithm(packerParams.ContentEncryptionAlgorithm),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt message")
	}

	return ret, nil
}

// ResolveRecipientKeyFromDIDDoc resolves recipient key from did document by key alg
func ResolveRecipientKeyFromDIDDoc(diddoc *verifiable.DIDDocument, keyAlg string) (jwk.Key, error) {
	if diddoc == nil {
		return nil, errors.New("did document is nil")
	}

	vms, err := diddoc.AllVerificationMethods().FilterBy(
		verifiable.WithJWKAlgorithm(keyAlg),
	)
	if err != nil {
		return nil, errors.Errorf(
			"failed to filter verification methods for DidDoc '%v': %v",
			diddoc.ID, err)
	}

	if len(vms) == 0 {
		return nil, errors.Errorf(
			"no verification methods found for key alg '%v' for DidDoc '%v'",
			keyAlg, diddoc.ID)
	}
	vm := vms[0]

	recipientJWKBytes, err := json.Marshal(vm.PublicKeyJwk)
	if err != nil {
		return nil, errors.Errorf(
			"failed to marshal public key to jwk for did %s: %v", diddoc.ID, err)
	}
	recipientKey, err := jwk.ParseKey(recipientJWKBytes)
	if err != nil {
		return nil, errors.Errorf(
			"failed to parse public key to jwk for did %s: %v", diddoc.ID, err)
	}
	_, ok := recipientKey.Algorithm()
	if !ok {
		return nil,
			errors.Errorf("missing alg in recipient key for did %s", diddoc.ID)
	}

	// if key id is not presented in recipient key, then set it from vm id
	// else use existing one
	kid, ok := recipientKey.KeyID()
	if !ok || kid == "" {
		if err := recipientKey.Set(jwk.KeyIDKey, vm.ID); err != nil {
			return nil, errors.Wrap(err, "failed to set kid in recipient key")
		} // set kid from vm id
	}

	return recipientKey, nil
}

// IsValidDirectKey checks that provided direct recipient key is valid for usage
func IsValidDirectKey(key jwk.Key) (jwk.Key, error) {
	keyAlg, ok := key.Algorithm()
	if !ok || keyAlg == nil {
		return nil, errors.New("missing alg in recipient key")
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return nil, errors.New("missing key id in recipient key")
	}
	return key, nil
}

// Unpack returns unpacked message from transport envelope
func (p *AnoncryptPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {
	payload, err := jweProvider.Decrypt(envelope, p.privateKeyResolver.Resolve)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt message")
	}

	msg := &iden3comm.BasicMessage{}
	if err = json.Unmarshal(payload, msg); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal message")
	}

	return msg, nil
}

// MediaType for iden3comm
func (p *AnoncryptPacker) MediaType() iden3comm.MediaType {
	return MediaTypeEncryptedMessage
}

// GetSupportedProfiles gets packer envelope (supported profiles) with options
func (p *AnoncryptPacker) GetSupportedProfiles() []string {
	return []string{
		fmt.Sprintf(
			"%s;env=%s;alg=%s",
			protocol.Iden3CommVersion1,
			p.MediaType(),
			strings.Join(jweProvider.SupportedKekAlgorithms, ","),
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

	if len(parsedProfile.AcceptCircuits) > 0 ||
		len(parsedProfile.AcceptJwzAlgorithms) > 0 ||
		len(parsedProfile.AcceptJwsAlgorithms) > 0 ||
		len(parsedProfile.AcceptAuthcryptAlgorithms) > 0 {
		return false
	}

	if len(parsedProfile.AcceptAnoncryptAlgorithms) == 0 {
		return true
	}

	for _, alg := range parsedProfile.AcceptAnoncryptAlgorithms {
		if jweProvider.IsSupportedKeyEncryptionAlgorithm(string(alg)) {
			return true
		}
	}
	return false

}
