//go:build jwx_es256k
// +build jwx_es256k

package packers

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1"
	bjj "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
)

type verificationType string

const (
	JsonWebKey2020                    verificationType = "JsonWebKey2020"
	EcdsaSecp256k1VerificationKey2019 verificationType = "EcdsaSecp256k1VerificationKey2019"
	EcdsaSecp256k1RecoveryMethod2020  verificationType = "EcdsaSecp256k1RecoveryMethod2020"
	EddsaBN256VerificaonKey           verificationType = "EddsaBN256VerificaonKey"
)

var supportedAlgorithms = map[jwa.SignatureAlgorithm]map[verificationType]struct{}{
	jwa.ES256K: {
		JsonWebKey2020:                    {},
		EcdsaSecp256k1VerificationKey2019: {},
		EcdsaSecp256k1RecoveryMethod2020:  {},
	},
	jwa.ES256: {
		JsonWebKey2020:                    {},
		EcdsaSecp256k1VerificationKey2019: {},
		EcdsaSecp256k1RecoveryMethod2020:  {},
	},
	BJJAlg: {
		EddsaBN256VerificaonKey: {},
		// "JsonWebKey2020":                    {}, for future use
	},
}

// MediaTypeSignedMessage is media type for jws
const MediaTypeSignedMessage iden3comm.MediaType = "application/iden3-signed-json"

// DIDResolverHandlerFunc resolves did
type DIDResolverHandlerFunc func(did string) (*verifiable.DIDDocument, error)

// Resolve function is responsible to call provided handler for resolve did document
func (f DIDResolverHandlerFunc) Resolve(did string) (*verifiable.DIDDocument, error) {
	return f(did)
}

type SignerResolverHandlerFunc func(kid string) (crypto.Signer, error)

func (f SignerResolverHandlerFunc) Resolve(kid string) (crypto.Signer, error) {
	return f(kid)
}

// JWSPacker is packer that use jws
type JWSPacker struct {
	didResolverHandler        DIDResolverHandlerFunc
	signerResolverHandlerFunc SignerResolverHandlerFunc
}

// SigningParams packer parameters for jws generation
type SigningParams struct {
	SenderDID string
	Alg       jwa.SignatureAlgorithm
	KID       string
	DIDDoc    *verifiable.DIDDocument
	iden3comm.PackerParams
}

// NewSigningParams defines the signing parameters for jws generation
func NewSigningParams() SigningParams {
	return SigningParams{}
}

func (s *SigningParams) Verify() error {
	if s.Alg == "" {
		return errors.New("alg is required for signing params")
	}
	if s.SenderDID == "" {
		return errors.New("sender did is required for signing params")
	}
	return nil
}

// NewJWSPacker creates new jws packer instance
func NewJWSPacker(
	didResolverHandler DIDResolverHandlerFunc,
	opaqueSignerResolverHandlerFunc SignerResolverHandlerFunc,
	// opaqueVerifierResolverHandlerFunc OpaqueVerifierResolverHandlerFunc,
) *JWSPacker {
	return &JWSPacker{
		didResolverHandler,
		opaqueSignerResolverHandlerFunc,
		// opaqueVerifierResolverHandlerFunc,
	}
}

// Pack returns packed message to transport envelope with a zero knowledge proof in JWS full serialized format
func (p *JWSPacker) Pack(
	payload []byte, params iden3comm.PackerParams) ([]byte, error) {

	signingParams, ok := params.(SigningParams)
	if !ok {
		return nil, errors.New("params must be SigningParams")
	}
	if err := signingParams.Verify(); err != nil {
		return nil, err
	}

	bm := &iden3comm.BasicMessage{}
	err := json.Unmarshal(payload, &bm)
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

	vm, err := lookupForKid(didDoc, signingParams.KID)
	if err != nil {
		return nil, err
	}

	var kid string
	if k, ok := vm.PublicKeyJwk["kid"].(string); ok {
		kid = k
	} else {
		kid = vm.ID
	}
	if kid == "" {
		return nil, errors.New("kid is required")
	}

	signer, err := p.signerResolverHandlerFunc.Resolve(kid)
	if err != nil {
		return nil, errors.New("can't resolve key")
	}

	hdrs := jws.NewHeaders()
	hdrs.Set(`kid`, kid)

	token, err := jws.Sign(
		payload,
		jws.WithKey(
			jwa.KeyAlgorithmFrom(signingParams.Alg),
			signer,
			jws.WithProtectedHeaders(hdrs),
		),
	)
	if err != nil {
		return nil, errors.Errorf("can't sign: %v", err)

	}

	return []byte(token), nil
}

// Unpack returns unpacked message from transport envelope with verification of signature
func (p *JWSPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {

	token, err := jws.Parse(envelope)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	sigs := token.Signatures()
	if len(sigs) != 1 {
		return nil, errors.New("invalid number of signatures")
	}
	kid := sigs[0].ProtectedHeaders().KeyID()
	if kid == "" {
		return nil, errors.New("kid header is required")
	}
	alg := sigs[0].ProtectedHeaders().Algorithm()
	if alg == "" {
		return nil, errors.New("alg header is required")
	}

	msg := &iden3comm.BasicMessage{}
	err = json.Unmarshal(token.Payload(), msg)
	if err != nil {
		return nil, errors.Errorf("invalid message payload: %v", err)
	}

	if msg.From == "" {
		return nil, errors.New("from field in did docuemnt is required")
	}

	didDoc, err := p.didResolverHandler.Resolve(msg.From)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	vm, err := lookupForKid(didDoc, kid)
	if err != nil {
		return nil, err
	}

	wk, err := extractVerifyKey(alg, vm)
	if err != nil {
		return nil, err
	}

	_, err = jws.Verify(envelope, wk)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return msg, nil
}

// MediaType for iden3comm that returns MediaTypeSignedMessage
func (p *JWSPacker) MediaType() iden3comm.MediaType {
	return MediaTypeSignedMessage
}

// lookupForKid looks for a verification method in the DID document that matches the given jwk kid or DID.
func lookupForKid(didDoc *verifiable.DIDDocument, kid string) (*verifiable.CommonVerificationMethod, error) {
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

func extractVerifyKey(alg jwa.SignatureAlgorithm, vm *verifiable.CommonVerificationMethod) (jws.VerifyOption, error) {
	supportedAlg, ok := supportedAlgorithms[alg]
	if !ok {
		return nil, errors.Errorf("unsupported algorithm: '%s'", alg)
	}
	_, ok = supportedAlg[verificationType(vm.Type)]
	if !ok {
		return nil, errors.Errorf("unsupported verification type: '%s'", vm.Type)
	}

	if len(vm.PublicKeyJwk) > 0 {
		vm.PublicKeyJwk["alg"] = alg
		bytesJWK, err := json.Marshal(vm.PublicKeyJwk)
		if err != nil {
			return nil, errors.Errorf("failed to marshal jwk: %v", err)
		}
		jwkKey, err := jwk.ParseKey(bytesJWK)
		if err != nil {
			return nil, errors.Errorf("failed to parse jwk: %v", err)
		}
		if jwkKey.Algorithm() != BJJAlg {
			return jws.WithKey(
				jwkKey.Algorithm(),
				jwkKey,
			), nil
		}
		bjjKey, err := parseBJJKey(jwkKey)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return jws.WithKey(
			jwkKey.Algorithm(),
			bjjKey,
		), nil
	}

	if vm.PublicKeyHex != "" {
		encodedKey, err := hex.DecodeString(vm.PublicKeyHex)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return jws.WithKey(
			jwa.KeyAlgorithmFrom(alg),
			newecdsa(encodedKey),
		), nil
	}

	if vm.PublicKeyBase58 != "" {
		encodedKey, err := base58.Decode(vm.PublicKeyBase58)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return jws.WithKey(
			jwa.KeyAlgorithmFrom(alg),
			newecdsa(encodedKey),
		), nil
	}

	return nil, errors.New("can't find public key")
}

func newecdsa(encodedKey []byte) ecdsa.PublicKey {
	return ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     new(big.Int).SetBytes(encodedKey[:32]),
		Y:     new(big.Int).SetBytes(encodedKey[32:]),
	}
}

func parseBJJKey(jwkKey jwk.Key) (*bjj.PublicKey, error) {
	ux, ok := jwkKey.Get("x")
	if !ok {
		return nil, errors.New("can't find x")
	}
	uy, _ := jwkKey.Get("y")
	if !ok {
		return nil, errors.New("can't find y")
	}
	x := big.NewInt(0).SetBytes(ux.([]byte))
	y := big.NewInt(0).SetBytes(uy.([]byte))

	bjjPoint := bjj.Point{X: x, Y: y}
	if !bjjPoint.InCurve() {
		return nil, errors.New("point is not in curve")
	}
	bjj := bjj.PublicKey(bjjPoint)

	return &bjj, nil
}
