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
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/iden3/iden3comm/v2/utils"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
)

var (
	defaultKEA                      = jwa.RSA_OAEP_256()
	defaultCEA                      = jwa.A256GCM()
	supportedAnoncryptKekAlgorithms = []string{defaultKEA.String(), jwa.ECDH_ES_A256KW().String()}
	supportedCekAlgorithms          = []string{defaultCEA.String(), jwa.A256CBC_HS512().String()}
)

// MediaTypeEncryptedMessage is media type for encrypted message
const MediaTypeEncryptedMessage iden3comm.MediaType = "application/iden3comm-encrypted-json"

// AnoncryptPacker is  packer for anon encryption / decryption
type AnoncryptPacker struct {
	kr            KeyResolverHandlerFunc
	didResolution DidDocumentResolverFunc
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
	} else if !isSupportedCekAlgorithm(p.ContentEncryptionAlgorithm) {
		return errors.New("unsupported content encryption algorithm")
	}

	for i := range p.Recipients {
		if p.Recipients[i].JWKAlg == "" {
			p.Recipients[i].JWKAlg = defaultKEA.String()
		} else if !isSupportedKekAlgorithm(p.Recipients[i].JWKAlg) {
			return errors.New("unsupported recipient key algorithm")
		}
	}

	if p.RecipientKey != nil {
		alg, ok := p.RecipientKey.Algorithm()
		if !ok || alg == nil {
			return errors.New("missing alg in recipient key")
		}
		if !isSupportedKekAlgorithm(alg.String()) {
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
	return &AnoncryptPacker{kr: kr, didResolution: dr}
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

	recipients := []jwe.EncryptOption{}
	for _, recipient := range packerParams.Recipients {
		resolution, err := p.didResolution(context.Background(), recipient.DID, nil)
		if err != nil {
			return nil, errors.Errorf("failed to resolve DidDoc for did %s: %v", recipient.DID, err)
		}

		recipientKey, err := p.resolveRecipientKeyFromDIDDoc(
			resolution.DidDocument, recipient.JWKAlg)
		if err != nil {
			return nil, errors.Errorf("failed to resolve recipient key for did %s: %v", recipient.DID, err)
		}

		recipients = append(recipients, recipientKey)
	}

	if packerParams.RecipientKey != nil {
		k, err := p.useDirectKey(packerParams.RecipientKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to use direct recipient key")
		}
		recipients = append(recipients, k)
	}

	if len(recipients) == 0 {
		return nil, errors.New("no recipient keys provided")
	}

	cea := jwa.NewContentEncryptionAlgorithm(packerParams.ContentEncryptionAlgorithm)

	headers := jwe.NewHeaders()
	if err := headers.Set(jwe.ContentEncryptionKey, cea); err != nil {
		return nil, errors.Wrap(err, "failed to set enc header")
	}
	if err := headers.Set(jwe.TypeKey, string(p.MediaType())); err != nil {
		return nil, errors.Wrap(err, "failed to set typ header")
	}

	opts := append([]jwe.EncryptOption{
		jwe.WithJSON(),
		jwe.WithContentEncryption(cea),
		jwe.WithProtectedHeaders(headers),
	}, recipients...)

	ret, err := jwe.Encrypt(payload, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt message")
	}

	return ret, nil
}

func (p *AnoncryptPacker) useDirectKey(key jwk.Key) (jwe.EncryptOption, error) {
	keyAlg, ok := key.Algorithm()
	if !ok || keyAlg == nil {
		return nil, errors.New("missing alg in recipient key")
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return nil, errors.New("missing key id in recipient key")
	}
	recipientHeaders := jwe.NewHeaders()
	if err := recipientHeaders.Set(jwe.KeyIDKey, kid); err != nil {
		return nil, errors.Wrap(err, "failed to set kid header")
	}
	return jwe.WithKey(keyAlg, key,
		jwe.WithPerRecipientHeaders(recipientHeaders),
	), nil
}

func (p *AnoncryptPacker) resolveRecipientKeyFromDIDDoc(diddoc *verifiable.DIDDocument, keyAlg string) (jwe.EncryptDecryptOption, error) {
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
	alg, ok := recipientKey.Algorithm()
	if !ok {
		return nil,
			errors.Errorf("missing alg in recipient key for did %s", diddoc.ID)
	}

	recipientHeaders := jwe.NewHeaders()
	if err := recipientHeaders.Set(jwe.KeyIDKey, vm.ID); err != nil {
		return nil, errors.Wrap(err, "failed to set kid header")
	}

	return jwe.WithKey(alg, recipientKey,
		jwe.WithPerRecipientHeaders(recipientHeaders),
	), nil
}

// Unpack returns unpacked message from transport envelope
func (p *AnoncryptPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {
	jweMessage, err := jwe.Parse(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwe token: %w", err)
	}

	for _, r := range jweMessage.Recipients() {
		kid, ok := r.Headers().KeyID()
		if !ok {
			continue
		}
		decryptionKey, err := p.kr.Resolve(kid)
		if err != nil {
			continue
		}

		alg, ok := r.Headers().Algorithm()
		if !ok {
			continue
		}
		if !isSupportedKekAlgorithm(alg.String()) {
			continue
		}

		payload, err := jwe.Decrypt(envelope, jwe.WithKey(alg, decryptionKey))
		if err != nil {
			continue
		}

		var msg iden3comm.BasicMessage
		err = json.Unmarshal(payload, &msg)
		if err != nil {
			return nil, err
		}
		return &msg, nil
	}

	return nil, errors.New("no recipient found")
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
			strings.Join(p.getSupportedKekAlgorithms(), ","),
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

	supportedAlgorithms := p.getSupportedKekAlgorithms()
	for _, alg := range parsedProfile.AcceptAnoncryptAlgorithms {
		for _, supportedAlg := range supportedAlgorithms {
			if string(alg) == supportedAlg {
				return true
			}
		}
	}
	return false

}

func (p *AnoncryptPacker) getSupportedKekAlgorithms() []string {
	return supportedAnoncryptKekAlgorithms
}

//nolint:unused // function might be used in future
func (p *AnoncryptPacker) getSupportedCekAlgorithms() []string {
	return supportedCekAlgorithms
}

func isSupportedKekAlgorithm(alg string) bool {
	for _, v := range supportedAnoncryptKekAlgorithms {
		if v == alg {
			return true
		}
	}
	return false
}

func isSupportedCekAlgorithm(alg string) bool {
	for _, v := range supportedCekAlgorithms {
		if v == alg {
			return true
		}
	}
	return false
}
