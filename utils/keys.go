package utils

import (
	"encoding/json"

	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
)

// ResolveRecipientKeyFromDIDDoc resolves recipient key from did document by key alg
func ResolveRecipientKeyFromDIDDoc(diddoc *verifiable.DIDDocument,
	filters ...verifiable.VerificationMethodFilterOpt) (jwk.Key, error) {
	if diddoc == nil {
		return nil, errors.New("did document is nil")
	}

	vms := diddoc.AllVerificationMethods()
	if len(filters) != 0 {
		var err error
		vms, err = vms.FilterBy(filters...)
		if err != nil {
			return nil, errors.Errorf(
				"failed to filter verification methods for DidDoc '%v': %v",
				diddoc.ID, err)
		}
	}

	if len(vms) == 0 {
		return nil, errors.Errorf("no verification methods found for DidDoc '%s'", diddoc.ID)
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
