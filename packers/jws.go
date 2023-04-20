package packers

import (
	"encoding/json"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"
	"github.com/pkg/errors"
	"gopkg.in/go-jose/go-jose.v2"
)

// MediaTypeSignedMessage is media type for jws
const MediaTypeSignedMessage iden3comm.MediaType = "application/iden3-signed-json"

// DIDResolverHandlerFunc resolves did
type DIDResolverHandlerFunc func(did string) (*verifiable.DIDDocument, error)

// Resolve function is responsible to call provided handler for resolve did document
func (f DIDResolverHandlerFunc) Resolve(did string) (*verifiable.DIDDocument, error) {
	return f(did)
}

type OpaqueSignerResolverHandlerFunc func(kid string) (jose.OpaqueSigner, error)

func (f OpaqueSignerResolverHandlerFunc) Resolve(kid string) (jose.OpaqueSigner, error) {
	return f(kid)
}

type OpaqueVerifierResolverHandlerFunc func(vm *verifiable.CommonVerificationMethod) (jose.OpaqueVerifier, error)

func (f OpaqueVerifierResolverHandlerFunc) Resolve(vm *verifiable.CommonVerificationMethod) (jose.OpaqueVerifier, error) {
	return f(vm)
}

// JWSPacker is packer that use jws
type JWSPacker struct {
	didResolverHandler                DIDResolverHandlerFunc
	opaqueSignerResolverHandlerFunc   OpaqueSignerResolverHandlerFunc
	opaqueVerifierResolverHandlerFunc OpaqueVerifierResolverHandlerFunc
}

// SigningParams packer parameters for jws generation
type SigningParams struct {
	SenderDID string
	Alg       jose.SignatureAlgorithm
	KID       string
	DIDDoc    *verifiable.DIDDocument
	iden3comm.PackerParams
}

// NewSigningParams defines the signing parameters for jws generation
func NewSigningParams() SigningParams {
	return SigningParams{}
}

// NewJWSPacker creates new jws packer instance
func NewJWSPacker(
	didResolverHandler DIDResolverHandlerFunc,
	opaqueSignerResolverHandlerFunc OpaqueSignerResolverHandlerFunc,
	opaqueVerifierResolverHandlerFunc OpaqueVerifierResolverHandlerFunc,
) *JWSPacker {
	return &JWSPacker{
		didResolverHandler,
		opaqueSignerResolverHandlerFunc,
		opaqueVerifierResolverHandlerFunc,
	}
}

// Pack returns packed message to transport envelope with a zero knowledge proof in JWS full serialized format
func (p *JWSPacker) Pack(
	payload []byte, params iden3comm.PackerParams) ([]byte, error) {

	// create hash of message
	var (
		err   error
		token *jose.JSONWebSignature
	)

	signingParams, ok := params.(SigningParams)
	if !ok {
		return nil, errors.New("params must be SigningParams")
	}

	bm := &iden3comm.BasicMessage{}
	err = json.Unmarshal(payload, &bm)
	if err != nil {
		return nil, errors.Errorf("invalid message payload: %v", err)
	}

	if bm.From != signingParams.SenderDID {
		return nil, errors.New("msg singer must me be msg sender")
	}

	didDoc := signingParams.DIDDoc
	if didDoc == nil {
		didDoc, err = p.didResolverHandler.Resolve(signingParams.SenderDID)
		if err != nil {
			return nil, errors.Errorf("resolve did failed: %v", err)
		}
	}

	vm, err := lookForKid(didDoc, signingParams.KID)
	if err != nil {
		return nil, err
	}

	var kid string
	if k, ok := vm.PublicKeyJwk["kid"].(string); ok {
		kid = k
	} else {
		kid = vm.ID
	}

	// TODO(illia-korotia): i think better to find key by vm
	opaqueSigner, err := p.opaqueSignerResolverHandlerFunc.Resolve(kid)
	if err != nil {
		return nil, errors.New("can't resolve key")
	}

	signer, err := jose.NewSigner(
		// TODO(illia-korotia): get alg from did doc
		jose.SigningKey{Algorithm: jose.ES256, Key: opaqueSigner},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderKey("kid"): kid,
			},
		})
	if err != nil {
		return nil, errors.Errorf("can't create signer: %v", err)
	}

	token, err = signer.Sign(payload)
	if err != nil {
		return nil, errors.Errorf("can't sign: %v", err)

	}

	t, err := token.CompactSerialize()
	if err != nil {
		return nil, errors.Errorf("can't serialize: %v", err)
	}
	return []byte(t), nil
}

// Unpack returns unpacked message from transport envelope with verification of signature
func (p *JWSPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {

	token, err := jose.ParseSigned(string(envelope))
	if err != nil {
		return nil, err
	}

	if len(token.Signatures) != 1 {
		return nil, errors.New("invalid number of signatures")
	}
	kid := token.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, errors.New("kid is empty")
	}

	msg := &iden3comm.BasicMessage{}
	err = json.Unmarshal(token.UnsafePayloadWithoutVerification(), msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if msg.From == "" {
		return nil, errors.New("from field is empty")
	}

	didDoc, err := p.didResolverHandler.Resolve(msg.From)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	vm, err := lookForKid(didDoc, kid)
	if err != nil {
		return nil, err
	}

	v, err := p.opaqueVerifierResolverHandlerFunc.Resolve(vm)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = token.Verify(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return msg, nil
}

// MediaType for iden3comm that returns MediaTypeSignedMessage
func (p *JWSPacker) MediaType() iden3comm.MediaType {
	return MediaTypeSignedMessage
}

// lookForKid looks for a verification method in the DID document that matches the given jwk kid or DID.
func lookForKid(didDoc *verifiable.DIDDocument, kid string) (*verifiable.CommonVerificationMethod, error) {
	vms := make([]verifiable.CommonVerificationMethod, 0,
		len(didDoc.VerificationMethod)+len(didDoc.Authentication))
	for _, auth := range didDoc.Authentication {
		vm := resolveAuthToVM(auth, didDoc.VerificationMethod)
		if vm == nil {
			continue
		}
		vms = append(vms, *vm)
	}
	vms = append(vms, didDoc.VerificationMethod...)

	if len(vms) == 0 {
		return nil, errors.New("no verification methods")
	}

	if kid == "" {
		return &vms[0], nil
	}

	for _, vm := range vms {
		if vm.ID == kid {
			return &vm, nil
		}
		if id, ok := vm.PublicKeyJwk["kid"]; ok && id == kid {
			return &vm, nil
		}
	}

	return nil, errors.New("can't find kid")
}

func resolveAuthToVM(
	auth verifiable.Authentication,
	vms []verifiable.CommonVerificationMethod,
) *verifiable.CommonVerificationMethod {
	if !auth.IsDID() {
		return &auth.CommonVerificationMethod
	}
	// make keys from authenication section more priority
	for _, vm := range vms {
		if auth.DID() == vm.ID {
			return &vm
		}
	}
	return nil
}
