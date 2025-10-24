package jwe

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
)

var (
	ErrDecryptionKeyNotFound = errors.New("decryption key not found")
)

var (
	// SupportedKekAlgorithms is a list of supported key encryption algorithms
	SupportedKekAlgorithms = []string{jwa.RSA_OAEP_256().String(), jwa.ECDH_ES_A256KW().String()}
	// SupportedCekAlgorithms is a list of supported content encryption algorithms
	SupportedCekAlgorithms = []string{jwa.A256GCM().String(), jwa.A256CBC_HS512().String()}
)

// IsSupportedKeyEncryptionAlgorithm checks if the provided key encryption algorithm is supported
func IsSupportedKeyEncryptionAlgorithm(alg string) bool {
	for _, a := range SupportedKekAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// IsSupportedContentEncryptionAlgorithm checks if the provided content encryption algorithm is supported
func IsSupportedContentEncryptionAlgorithm(alg string) bool {
	for _, a := range SupportedCekAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// EncryptOption defines a function type for setting options on the encryption process
type EncryptOption func(*encryptOptions)

type encryptOptions struct {
	additionalProtectedHeaders jwe.Headers
	contentEncryptionAlgorithm string
}

// WithAdditionalProtectedHeaders adds additional protected headers to the JWE
func WithAdditionalProtectedHeaders(headers jwe.Headers) EncryptOption {
	return func(o *encryptOptions) {
		o.additionalProtectedHeaders = headers
	}
}

// WithContentEncryptionAlgorithm sets the content encryption algorithm for the JWE
func WithContentEncryptionAlgorithm(alg string) EncryptOption {
	return func(o *encryptOptions) {
		o.contentEncryptionAlgorithm = alg
	}
}

// Encrypt encrypts the payload for the given recipient keys using the specified options
func Encrypt(payload []byte, recipients []jwk.Key, opts ...EncryptOption) ([]byte, error) {
	encOpts := &encryptOptions{}
	for _, opt := range opts {
		opt(encOpts)
	}

	if len(recipients) == 0 {
		return nil, errors.New("no recipient keys provided")
	}

	contentEncryptionAlgorithm := encOpts.contentEncryptionAlgorithm
	if !IsSupportedContentEncryptionAlgorithm(
		contentEncryptionAlgorithm,
	) {
		return nil, errors.Errorf("contentEncryptionAlgorithm '%s' is not supported",
			contentEncryptionAlgorithm)
	}

	withKeys := []jwe.EncryptOption{}
	for _, recipient := range recipients {
		recAlg, ok := recipient.Algorithm()
		if !ok || recAlg == nil {
			return nil, errors.New("missing alg in recipient key")
		}
		if !IsSupportedKeyEncryptionAlgorithm(recAlg.String()) {
			return nil, errors.Errorf("key alg '%s' is not supported", recAlg.String())
		}
		withKeys = append(withKeys, jwe.WithKey(recAlg, recipient))
	}

	cea := jwa.NewContentEncryptionAlgorithm(contentEncryptionAlgorithm)
	headers := jwe.NewHeaders()
	if err := headers.Set(jwe.ContentEncryptionKey, cea); err != nil {
		return nil, errors.Wrap(err, "failed to set enc header")
	}

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
		jwe.WithLegacyHeaderMerging(false),
	}, withKeys...)

	ret, err := jwe.Encrypt(payload, jweOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt message")
	}

	return ret, nil
}

// KeyResolutionFunc defines a function type for resolving keys by their ID
type KeyResolutionFunc func(keyID string) (key interface{}, err error)

// Decrypt decrypts the JWE envelope using the provided key resolution function
func Decrypt(envelope []byte, fn KeyResolutionFunc) ([]byte, error) {
	customKeyProvider := func(ctx context.Context, sink jwe.KeySink, r jwe.Recipient, msg *jwe.Message) error {
		mergedHeaders, err := mergeHeaders(msg.ProtectedHeaders(), msg.UnprotectedHeaders(), r.Headers())
		if err != nil {
			return fmt.Errorf("failed to merge JWE headers: %w", err)
		}

		alg, ok := mergedHeaders.Algorithm()
		if !ok || alg.String() == "" {
			return fmt.Errorf("recipient has no algorithm")
		}
		if !IsSupportedKeyEncryptionAlgorithm(alg.String()) {
			return fmt.Errorf("unsupported key encryption algorithm: %s", alg.String())
		}

		enc, ok := mergedHeaders.ContentEncryption()
		if !ok || enc.String() == "" {
			return fmt.Errorf("message has no content encryption algorithm")
		}
		if !IsSupportedContentEncryptionAlgorithm(enc.String()) {
			return fmt.Errorf("unsupported content encryption algorithm: %s", enc.String())
		}

		kid, ok := mergedHeaders.KeyID()
		if !ok || kid == "" {
			return fmt.Errorf("recipient has no key ID")
		}
		decryptionKey, err := fn(kid)
		if err != nil {
			return err
		}
		sink.Key(alg, decryptionKey)
		return nil
	}

	payload, err := jwe.Decrypt(envelope, jwe.WithKeyProvider(jwe.KeyProviderFunc(customKeyProvider)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", err, ErrDecryptionKeyNotFound)
	}
	return payload, nil
}

func mergeHeaders(protected, unprotected, perRecipient jwe.Headers) (jwe.Headers, error) {
	var allKeys []string
	if protected != nil {
		allKeys = append(allKeys, protected.Keys()...)
	}
	if unprotected != nil {
		allKeys = append(allKeys, unprotected.Keys()...)
	}
	if perRecipient != nil {
		allKeys = append(allKeys, perRecipient.Keys()...)
	}

	seen := make(map[string]struct{})
	for _, key := range allKeys {
		if _, ok := seen[key]; ok {
			return nil, errors.Errorf("duplicate header key found: %s", key)
		}
		seen[key] = struct{}{}
	}

	// Merge headers (no duplicates, so safe to merge)
	result := jwe.NewHeaders()
	if protected != nil {
		if err := protected.Copy(result); err != nil {
			return nil, errors.Wrap(err, "failed to merge protected headers")
		}
	}
	if unprotected != nil {
		var err error
		result, err = result.Merge(unprotected)
		if err != nil {
			return nil, errors.Wrap(err, "failed to merge unprotected headers")
		}
	}
	if perRecipient != nil {
		var err error
		result, err = result.Merge(perRecipient)
		if err != nil {
			return nil, errors.Wrap(err, "failed to merge per-recipient headers")
		}
	}

	return result, nil
}
