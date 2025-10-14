package jwe

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
)

var (
	supportedAnoncryptKekAlgorithms = []string{jwa.RSA_OAEP_256().String(), jwa.ECDH_ES_A256KW().String()}
	supportedCekAlgorithms          = []string{jwa.A256GCM().String(), jwa.A256CBC_HS512().String()}
)

func IsSupportedKeyEncryptionAlgorithm(alg string) bool {
	for _, a := range supportedAnoncryptKekAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

func IsSupportedContentEncryptionAlgorithm(alg string) bool {
	for _, a := range supportedCekAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

type AnoncryptRecipients struct {
	DID    string
	JWKAlg string
}

type Provider struct {
	keyResolution    func(keyID string) (key interface{}, err error)
	didDocResolution func(ctx context.Context, did string, opts *services.ResolverOpts) (*document.DidResolution, error)
}

func NewJWEProvider(
	keyResolution func(keyID string) (key interface{}, err error),
	didDocResolution func(ctx context.Context, did string, opts *services.ResolverOpts) (*document.DidResolution, error),
) *Provider {
	return &Provider{
		keyResolution:    keyResolution,
		didDocResolution: didDocResolution,
	}
}

type EncryptOption func(*encryptOptions)

type encryptOptions struct {
	additionalProtectedHeaders jwe.Headers
}

// WithAdditionalProtectedHeaders adds additional protected headers to the JWE
func WithAdditionalProtectedHeaders(headers jwe.Headers) EncryptOption {
	return func(o *encryptOptions) {
		o.additionalProtectedHeaders = headers
	}
}

func (p *Provider) Encrypt(payload []byte, recipientKey jwk.Key, recipients []AnoncryptRecipients, contentEncryptionAlgorithm string, opts ...EncryptOption) ([]byte, error) {
	// Apply options
	encOpts := &encryptOptions{}
	for _, opt := range opts {
		opt(encOpts)
	}

	if recipientKey == nil && len(recipients) == 0 {
		return nil, errors.New("either recipientKey or recipients must be provided")
	}
	if contentEncryptionAlgorithm == "" {
		return nil, errors.New("contentEncryptionAlgorithm must be provided")
	}
	if !IsSupportedContentEncryptionAlgorithm(contentEncryptionAlgorithm) {
		return nil, errors.Errorf("contentEncryptionAlgorithm '%s' is not supported", contentEncryptionAlgorithm)
	}

	withKeys := []jwe.EncryptOption{}
	for _, recipient := range recipients {
		resolution, err := p.didDocResolution(context.Background(), recipient.DID, nil)
		if err != nil {
			return nil, errors.Errorf("failed to resolve DidDoc for did %s: %v", recipient.DID, err)
		}

		recipientKey, err := p.resolveRecipientKeyFromDIDDoc(
			resolution.DidDocument, recipient.JWKAlg)
		if err != nil {
			return nil, errors.Errorf("failed to resolve recipient key for did %s: %v", recipient.DID, err)
		}

		withKeys = append(withKeys, recipientKey)
	}

	if recipientKey != nil {
		k, err := p.useDirectKey(recipientKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to use direct recipient key")
		}
		withKeys = append(withKeys, k)
	}

	if len(withKeys) == 0 {
		return nil, errors.New("no recipient keys provided")
	}

	cea := jwa.NewContentEncryptionAlgorithm(contentEncryptionAlgorithm)

	headers := jwe.NewHeaders()
	if err := headers.Set(jwe.ContentEncryptionKey, cea); err != nil {
		return nil, errors.Wrap(err, "failed to set enc header")
	}

	// Add additional protected headers if provided
	if encOpts.additionalProtectedHeaders != nil {
		var err error
		headers, err = headers.Merge(encOpts.additionalProtectedHeaders)
		if err != nil {
			return nil, errors.Wrap(err, "failed to merge additional protected headers")
		}
	}

	jweOpts := append([]jwe.EncryptOption{
		jwe.WithJSON(),
		jwe.WithContentEncryption(cea),
		jwe.WithProtectedHeaders(headers),
	}, withKeys...)

	ret, err := jwe.Encrypt(payload, jweOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt message")
	}

	return ret, nil
}

func (p *Provider) Decrypt(envelope []byte) ([]byte, error) {
	jweMessage, err := jwe.Parse(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwe token: %w", err)
	}

	for _, r := range jweMessage.Recipients() {
		kid, ok := r.Headers().KeyID()
		if !ok {
			continue
		}
		decryptionKey, err := p.keyResolution(kid)
		if err != nil {
			continue
		}

		alg, ok := r.Headers().Algorithm()
		if !ok {
			continue
		}
		if !IsSupportedKeyEncryptionAlgorithm(alg.String()) {
			continue
		}

		cekAlg, ok := jweMessage.ProtectedHeaders().ContentEncryption()
		if !ok {
			continue
		}
		if !IsSupportedContentEncryptionAlgorithm(cekAlg.String()) {
			continue
		}

		payload, err := jwe.Decrypt(envelope, jwe.WithKey(alg, decryptionKey))
		if err != nil {
			continue
		}

		return payload, nil
	}

	return nil, errors.New("no matching key found for decryption")
}

func (p *Provider) resolveRecipientKeyFromDIDDoc(diddoc *verifiable.DIDDocument, keyAlg string) (jwe.EncryptDecryptOption, error) {
	if diddoc == nil {
		return nil, errors.New("did document is nil")
	}

	if !IsSupportedKeyEncryptionAlgorithm(keyAlg) {
		return nil, errors.Errorf("key alg '%s' is not supported", keyAlg)
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

func (p *Provider) useDirectKey(key jwk.Key) (jwe.EncryptOption, error) {
	keyAlg, ok := key.Algorithm()
	if !ok || keyAlg == nil {
		return nil, errors.New("missing alg in recipient key")
	}
	if !IsSupportedKeyEncryptionAlgorithm(keyAlg.String()) {
		return nil, errors.Errorf("key alg '%s' is not supported", keyAlg.String())
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
