package packers

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/dustinxie/ecc"
	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"
	"github.com/iden3/iden3comm/packers/providers/bjj"
	"github.com/iden3/iden3comm/packers/providers/es256k"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
)

type verificationType string

// List of supported verification types
const (
	JSONWebKey2020                    verificationType = "JsonWebKey2020"
	EcdsaSecp256k1VerificationKey2019 verificationType = "EcdsaSecp256k1VerificationKey2019"
	EcdsaSecp256k1RecoveryMethod2020  verificationType = "EcdsaSecp256k1RecoveryMethod2020"
	EddsaBJJVerificationKey           verificationType = "EddsaBJJVerificationKey"
)

var supportedAlgorithms = map[jwa.SignatureAlgorithm]map[verificationType]struct{}{
	jwa.ES256K: {
		JSONWebKey2020:                    {},
		EcdsaSecp256k1VerificationKey2019: {},
		EcdsaSecp256k1RecoveryMethod2020:  {},
	},
	"ES256K-R": {
		JSONWebKey2020:                    {},
		EcdsaSecp256k1VerificationKey2019: {},
		EcdsaSecp256k1RecoveryMethod2020:  {},
	},
	bjj.Alg: {
		EddsaBJJVerificationKey: {},
		// "JsonWebKey2020":                    {}, for future use
	},
}

// MediaTypeSignedMessage is media type for jws
const MediaTypeSignedMessage iden3comm.MediaType = "application/iden3comm-signed-json"

// DIDResolverHandlerFunc resolves did
type DIDResolverHandlerFunc func(did string) (*verifiable.DIDDocument, error)

// Resolve function is responsible to call provided handler for resolve did document
func (f DIDResolverHandlerFunc) Resolve(did string) (*verifiable.DIDDocument, error) {
	return f(did)
}

// SignerResolverHandlerFunc resolves signer
type SignerResolverHandlerFunc func(kid string) (crypto.Signer, error)

// Resolve function return signer by kid
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
	Alg    jwa.SignatureAlgorithm
	KID    string
	DIDDoc *verifiable.DIDDocument
	iden3comm.PackerParams
}

// Register custom providers for jwx
//
//nolint:gochecknoinits // Need to register BJJAlg
func init() {
	registerBJJProvider()
}

func registerBJJProvider() {
	bp := &bjj.Provider{}
	jws.RegisterSigner(
		bp.Algorithm(),
		jws.SignerFactoryFn(
			func() (jws.Signer, error) {
				return bp, nil
			},
		))
	jws.RegisterVerifier(
		bp.Algorithm(),
		jws.VerifierFactoryFn(
			func() (jws.Verifier, error) {
				return bp, nil
			}),
	)
}

// ErrorVerificationMethodNotFound is return where no verification method found for specified kid
var ErrorVerificationMethodNotFound = errors.New("specified verification method not found")

// NewSigningParams defines the signing parameters for jws generation
func NewSigningParams() SigningParams {
	return SigningParams{}
}

// Verify checks if signing params are valid
func (s *SigningParams) Verify() error {
	if s.Alg == "" {
		return errors.New("alg is required for signing params")
	}
	return nil
}

// NewJWSPacker creates new jws packer instance
func NewJWSPacker(
	didResolverHandler DIDResolverHandlerFunc,
	signerResolverHandlerFunc SignerResolverHandlerFunc,
) *JWSPacker {
	return &JWSPacker{
		didResolverHandler,
		signerResolverHandlerFunc,
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

	didDoc := signingParams.DIDDoc
	if didDoc == nil {
		didDoc, err = p.didResolverHandler.Resolve(bm.From)
		if err != nil {
			return nil, errors.Errorf("resolve did failed: %v", err)
		}
	}

	vms, err := resolveVerificationMethods(didDoc)
	if err != nil {
		return nil, err
	}

	vm, err := findVerificationMethodByID(vms, signingParams.KID)
	if err != nil {
		return nil, err
	}

	kid := vm.ID

	signer, err := p.signerResolverHandlerFunc.Resolve(kid)
	if err != nil {
		return nil, errors.New("can't resolve key")
	}

	hdrs := jws.NewHeaders()
	if err = hdrs.Set("kid", kid); err != nil {
		return nil, errors.Errorf("can't set kid: %v", err)
	}
	if err = hdrs.Set("typ", string(MediaTypeSignedMessage)); err != nil {
		return nil, errors.Errorf("can't set typ: %v", err)
	}

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

	return token, nil
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
		return nil, errors.New("from field in did document is required")
	}

	parsedKid := strings.Split(kid, "#")
	if len(parsedKid) < 1 {
		return nil, errors.New("kid is expected in format of valid did string")
	}
	if kid != "" && parsedKid[0] != msg.From {
		return nil, errors.New("sender must use equal kid that contains did identifier")
	}

	didDoc, err := p.didResolverHandler.Resolve(msg.From)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	vms, err := resolveVerificationMethods(didDoc)
	if err != nil {
		return nil, err
	}

	if kid != "" {
		var vm verifiable.CommonVerificationMethod
		vm, err = findVerificationMethodByID(vms, kid)
		if err != nil {
			return nil, err
		}
		vms = []verifiable.CommonVerificationMethod{vm}
	}

	for i := range vms {

		err = checkAlgorithmSupport(alg, vms[i])
		if err != nil {
			// skip verification method check if algorithm is not supported
			continue
		}
		if vms[i].BlockchainAccountID == "" && vms[i].EthereumAddress == "" {
			wk, err := extractVerificationKey(alg, vms[i])
			if err != nil {
				continue
			}
			_, err = jws.Verify(envelope, wk)
			if err != nil {
				continue
			}
		} else {
			base64Token, err := jws.Compact(token)
			if err != nil {
				continue
			}
			base64TokenParts := strings.Split(string(base64Token), ".")
			signedData := base64TokenParts[0] + "." + base64TokenParts[1]
			hash := sha256.Sum256([]byte(signedData))
			sig := token.Signatures()[0].Signature()
			recoveredKey, err := ecc.RecoverEthereum(hash[:], sig)
			if err != nil {
				continue
			}

			ethAddress := "0x" + hex.EncodeToString(keccak256.Hash(recoveredKey[1:])[12:])
			if vms[i].EthereumAddress != "" {
				if !strings.EqualFold(ethAddress, vms[i].EthereumAddress) {
					continue
				}
			} else {
				blockchainAccountIDParts := strings.Split(vms[i].BlockchainAccountID, ":")
				address := blockchainAccountIDParts[len(blockchainAccountIDParts)-1]
				if !strings.EqualFold(address, ethAddress) {
					// skip because of invalid signature from blockchain account id
					continue
				}
			}

		}

		return msg, nil
	}

	return nil, errors.New("could not verify message using any of the signatures or keys")
}

// MediaType for iden3comm that returns MediaTypeSignedMessage
func (p *JWSPacker) MediaType() iden3comm.MediaType {
	return MediaTypeSignedMessage
}

// resolveVerificationMethods looks for all verification methods in the DID document.
func resolveVerificationMethods(didDoc *verifiable.DIDDocument) ([]verifiable.CommonVerificationMethod, error) {
	vms := make([]verifiable.CommonVerificationMethod, 0,
		len(didDoc.Authentication))

	// first - add verification methods for authentication

	for i := range didDoc.Authentication {
		vm, err := resolveAuthToVM(
			didDoc.Authentication[i],
			didDoc.VerificationMethod,
		)
		if err != nil {
			continue
		}
		vms = append(vms, vm)
	}
	// first - add other methods for authentication
	for i := range didDoc.VerificationMethod {
		_, err := findVerificationMethodByID(vms, didDoc.VerificationMethod[i].ID)
		if err != nil && err == ErrorVerificationMethodNotFound {
			vms = append(vms, didDoc.VerificationMethod[i])
		}
	}

	if len(vms) == 0 {
		return vms, errors.New("no verification methods")
	}

	return vms, nil
}

func resolveAuthToVM(
	auth verifiable.Authentication,
	vms []verifiable.CommonVerificationMethod,
) (verifiable.CommonVerificationMethod, error) {
	if !auth.IsDID() {
		return auth.CommonVerificationMethod, nil
	}
	// make keys from authentication section more priority
	for i := range vms {
		if auth.DID() == vms[i].ID {
			return vms[i], nil
		}
	}
	return verifiable.CommonVerificationMethod{}, errors.New("not found")
}
func findVerificationMethodByID(
	vms []verifiable.CommonVerificationMethod,
	id string,
) (verifiable.CommonVerificationMethod, error) {
	if id == "" {
		return vms[0], nil
	}
	for i := range vms {
		if id == vms[i].ID {
			return vms[i], nil
		}
	}
	return verifiable.CommonVerificationMethod{}, ErrorVerificationMethodNotFound
}

func extractVerificationKey(alg jwa.SignatureAlgorithm, vm verifiable.CommonVerificationMethod) (jws.VerifyOption, error) {
	switch {
	case len(vm.PublicKeyJwk) > 0:
		return processJWK(string(alg), vm)
	case vm.PublicKeyHex != "":
		encodedKey, err := hex.DecodeString(vm.PublicKeyHex)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return jws.WithKey(
			jwa.KeyAlgorithmFrom(alg),
			es256k.NewECDSA(encodedKey),
		), nil
	case vm.PublicKeyBase58 != "":
		encodedKey, err := base58.Decode(vm.PublicKeyBase58)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return jws.WithKey(
			jwa.KeyAlgorithmFrom(alg),
			es256k.NewECDSA(encodedKey),
		), nil
	}

	return nil, errors.New("can't find public key")
}

func checkAlgorithmSupport(alg jwa.SignatureAlgorithm, vm verifiable.CommonVerificationMethod) error {
	supportedAlg, ok := supportedAlgorithms[alg]
	if !ok {
		return errors.Errorf("unsupported algorithm: '%s'", alg)
	}
	_, ok = supportedAlg[verificationType(vm.Type)]
	if !ok {
		return errors.Errorf("unsupported verification type: '%s'", vm.Type)
	}
	return nil
}

func processJWK(alg string, vm verifiable.CommonVerificationMethod) (jws.VerifyOption, error) {
	vm.PublicKeyJwk["alg"] = alg
	bytesJWK, err := json.Marshal(vm.PublicKeyJwk)
	if err != nil {
		return nil, errors.Errorf("failed to marshal jwk: %v", err)
	}
	jwkKey, err := jwk.ParseKey(bytesJWK)
	if err != nil {
		return nil, errors.Errorf("failed to parse jwk: %v", err)
	}

	var withKey jws.VerifyOption
	switch jwkKey.Algorithm() {
	case bjj.Alg:
		bjjKey, err := bjj.ParseKey(jwkKey)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		withKey = jws.WithKey(jwkKey.Algorithm(), bjjKey)
	case jwa.ES256K:
		// to ensure the support of es256k while parsing jwk key,
		// it is advisable to manually generate the key for es256k
		// rather than relying on build tags.
		ecdsaKey, err := es256k.ParseKey(jwkKey)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		withKey = jws.WithKey(jwkKey.Algorithm(), ecdsaKey)
	default:
		return nil, errors.Errorf("unsupported algorithm: %s", jwkKey.Algorithm())
	}

	return withKey, nil
}
