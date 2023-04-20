package packers

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	ethc "github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/go-jose/go-jose.v2"
)

type OpaqueSignerMock struct {
	keys map[jose.SignatureAlgorithm]interface{}
}

func (o *OpaqueSignerMock) Public() *jose.JSONWebKey {
	// need to fill for verification
	return &jose.JSONWebKey{}
}

func (o *OpaqueSignerMock) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.ES256,
		jose.EdDSA,
	}
}

func (o *OpaqueSignerMock) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	pk, ok := o.keys[alg]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	switch v := pk.(type) {
	case *ecdsa.PrivateKey:
		hash := ethc.Keccak256Hash(payload)
		signature, err := ethc.Sign(hash.Bytes(), v)
		if err != nil {
			return nil, err
		}
		fmt.Println("signature after sign", hex.EncodeToString(signature))
		fmt.Println("hash after sign", hex.EncodeToString(hash.Bytes()))
		return signature, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

type OpaqueVerifierMock struct {
	keys map[jose.SignatureAlgorithm]interface{}
}

func (o *OpaqueVerifierMock) VerifyPayload(payload, signature []byte, alg jose.SignatureAlgorithm) error {
	pk, ok := o.keys[alg]
	if !ok {
		return fmt.Errorf("key not found")
	}
	switch v := pk.(type) {
	case *ecdsa.PublicKey:
		hash := ethc.Keccak256Hash(payload)
		fmt.Println("signature while verify", hex.EncodeToString(signature))
		fmt.Println("hash while verify", hex.EncodeToString(hash.Bytes()))
		ok := ethc.VerifySignature(ethc.FromECDSAPub(v), hash.Bytes(), signature)
		if !ok {
			return fmt.Errorf("invalid signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type")
	}
}

func TestJWSPacker_Pack(t *testing.T) {

	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
			return &verifiable.DIDDocument{
				Context: []string{
					"https://www.w3.org/ns/did/v1",
				},
				VerificationMethod: []verifiable.CommonVerificationMethod{
					{
						ID:         "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#key-1",
						Type:       "EcdsaSecp256k1VerificationKey2019",
						Controller: "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29",
						PublicKeyJwk: map[string]interface{}{
							"kty": "EC",
							"crv": "secp256k1",
							"x":   "6375398197028747898237416288959136228073977939523014364158452824509261966171",
							"y":   "48069307313191909360943659894000451607427122551771560662505794349254873224636",
						},
					},
				},
			}, nil
		}),

		opaqueSignerResolverHandlerFunc: OpaqueSignerResolverHandlerFunc(func(kid string) (jose.OpaqueSigner, error) {
			D, _ := big.NewInt(0).SetString(
				"17148312315387517831334631018406053846065789047950971654894255476413360159076", 10,
			)
			x, _ := big.NewInt(0).SetString("6375398197028747898237416288959136228073977939523014364158452824509261966171", 10)
			y, _ := big.NewInt(0).SetString("48069307313191909360943659894000451607427122551771560662505794349254873224636", 10)

			privateKey := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: ethc.S256(),
					X:     x,
					Y:     y,
				},
				D: D,
			}
			return &OpaqueSignerMock{
				keys: map[jose.SignatureAlgorithm]interface{}{
					jose.ES256: privateKey,
				},
			}, nil
		}),
	}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	_ = "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"

	token, err := p.Pack(msgBytes, SigningParams{SenderDID: `did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29`})
	require.Nil(t, err)
	fmt.Println("JWS token:", string(token))
}

func TestJWSPacker_Unpack(t *testing.T) {

	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
			return &verifiable.DIDDocument{
				Context: []string{
					"https://www.w3.org/ns/did/v1",
				},
				VerificationMethod: []verifiable.CommonVerificationMethod{
					{
						ID:         "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#key-1",
						Type:       "EcdsaSecp256k1VerificationKey2019",
						Controller: "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29",
						PublicKeyJwk: map[string]interface{}{
							"kty": "EC",
							"crv": "secp256k1",
							"x":   "6375398197028747898237416288959136228073977939523014364158452824509261966171",
							"y":   "48069307313191909360943659894000451607427122551771560662505794349254873224636",
						},
					},
				},
			}, nil
		}),

		opaqueVerifierResolverHandlerFunc: OpaqueVerifierResolverHandlerFunc(
			func(vm *verifiable.CommonVerificationMethod) (jose.OpaqueVerifier, error) {
				x, _ := big.NewInt(0).SetString("6375398197028747898237416288959136228073977939523014364158452824509261966171", 10)
				y, _ := big.NewInt(0).SetString("48069307313191909360943659894000451607427122551771560662505794349254873224636", 10)

				k := &ecdsa.PublicKey{
					Curve: ethc.S256(),
					X:     x,
					Y:     y,
				}

				return &OpaqueVerifierMock{
					keys: map[jose.SignatureAlgorithm]interface{}{
						jose.ES256: k,
					},
				}, nil
			}),
	}

	msgZKP := []byte(`eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp4NGpjSFA0WEhUSzN2WDU4QUhaUHlIRThrWWpuZXlFNkZaUmZ6N0syOSNrZXktMSJ9.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp4NGpjSFA0WEhUSzN2WDU4QUhaUHlIRThrWWpuZXlFNkZaUmZ6N0syOSIsImJvZHkiOnsic2NvcGUiOlt7InR5cGUiOiJ6ZXJva25vd2xlZGdlIiwiY2lyY3VpdF9pZCI6ImF1dGgiLCJwdWJfc2lnbmFscyI6WyIxIiwiMTgzMTE1NjA1MjUzODMzMTk3MTkzMTEzOTQ5NTcwNjQ4MjAwOTEzNTQ5NzYzMTA1OTk4MTg3OTcxNTcxODk1Njg2MjE0NjY5NTA4MTEiLCIzMjM0MTY5MjUyNjQ2NjYyMTc2MTcyODg1Njk3NDI1NjQ3MDM2MzI4NTA4MTYwMzU3NjEwODQwMDI3MjAwOTAzNzczNTMyOTc5MjAiXSwicHJvb2ZfZGF0YSI6eyJwaV9hIjpbIjExMTMwODQzMTUwNTQwNzg5Mjk5NDU4OTkwNTg2MDIwMDAwNzE5MjgwMjQ2MTUzNzk3ODgyODQzMjE0MjkwNTQxOTgwNTIyMzc1MDcyIiwiMTMwMDg0MTkxMjk0Mzc4MTcyMzAyMjAzMjM1NTgzNjg5MzgzMTEzMjkyMDc4Mzc4ODQ1NTUzMTgzODI1NDQ2NTc4NDYwNTc2MjcxMyIsIjEiXSwicGlfYiI6W1siMjA2MTU3Njg1MzY5ODg0MzgzMzY1Mzc3Nzc5MDkwNDIzNTIwNTYzOTI4NjIyNTE3ODU3MjI3OTY2Mzc1OTAyMTIxNjA1NjEzNTE2NTYiLCIxMDM3MTE0NDgwNjEwNzc3ODg5MDUzODg1NzcwMDg1NTEwODY2NzYyMjA0MjIxNTA5Njk3MTc0NzIwMzEwNTk5NzQ1NDYyNTgxNDA4MCJdLFsiMTk1OTg1NDEzNTA4MDQ0Nzg1NDkxNDEyMDc4MzUwMjg2NzExMTEwNjM5MTU2MzU1ODA2Nzk2OTQ5MDc2MzU5MTQyNzk5Mjg2Nzc4MTIiLCIxNTI2NDU1MzA0NTUxNzA2NTY2OTE3MTU4NDk0Mzk2NDMyMjExNzM5NzY0NTE0NzAwNjkwOTE2NzQyNzgwOTgzNzkyOTQ1ODAxMjkxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTY0NDMzMDkyNzk4MjU1MDg4OTMwODYyNTEyOTAwMDM5MzY5MzUwNzczNDg3NTQwOTc0NzA4MTg1MjM1NTgwODI1MDIzNjQ4MjIwNDkiLCIyOTg0MTgwMjI3NzY2MDQ4MTAwNTEwMTIwNDA3MTUwNzUyMDUyMzM0NTcxODc2NjgxMzA0OTk5NTk1NTQ0MTM4MTU1NjExOTYzMjczIiwiMSJdLCJwcm90b2NvbCI6IiJ9fV19fQ.yhZrlAyIVIgBy4D5vIiXgwEzGfuucvz_ICvdTfcj-g8eCCoGb1NzKisfzBzS_SH2bHPiqxXWs8ZwCJRxVOtQiAE`)
	iden3msg, err := p.Unpack(msgZKP)
	require.NoError(t, err)
	msgBytes, err := json.Marshal(iden3msg)
	require.Nil(t, err)
	var authResponse protocol.AuthorizationResponseMessage
	err = json.Unmarshal(msgBytes, &authResponse)
	require.Nil(t, err)
	fmt.Println(string(msgBytes))
	require.Equal(t, protocol.AuthorizationResponseMessageType, authResponse.Type)
	require.Len(t, authResponse.Body.Scope, 1)

}

func TestLookForKid(t *testing.T) {
	tests := []struct {
		name           string
		didDocFileName string
		kid            string
		expectedKey    *verifiable.CommonVerificationMethod
	}{
		{
			name:           "Try to find vm by did",
			didDocFileName: "diddocument_with_jws_did.json",
			kid:            "#vm-1",
			expectedKey: &verifiable.CommonVerificationMethod{
				ID:         "#vm-1",
				Controller: "did:test:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w",
				Type:       "EcdsaSecp256k1VerificationKey2019",
				PublicKeyJwk: map[string]interface{}{
					"testID": "1",
					"kty":    "EC",
					"crv":    "secp256k1",
					"x":      "WfY7Px6AgH6x-_dgAoRbg8weYRJA36ON-gQiFnETrqw",
					"y":      "IzFx3BUGztK0cyDStiunXbrZYYTtKbOUzx16SUK0sAY",
				},
			},
		},
		{
			name:           "Try to find vm by kid in jwk",
			didDocFileName: "diddocument_with_jws_kid.json",
			kid:            "umQfTkR8vvZ9JPhl",
			expectedKey: &verifiable.CommonVerificationMethod{
				ID:         "#someKeyId",
				Controller: "did:test:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w",
				Type:       "EcdsaSecp256k1VerificationKey2019",
				PublicKeyJwk: map[string]interface{}{
					"testID": "2",
					"kty":    "EC",
					"crv":    "secp256k1",
					"kid":    "umQfTkR8vvZ9JPhl",
					"x":      "WfY7Px6AgH6x-_dgAoRbg8weYRJA36ON-gQiFnETrqw",
					"y":      "IzFx3BUGztK0cyDStiunXbrZYYTtKbOUzx16SUK0sAY",
				},
			},
		},
		{
			name:           "Try to find vm by did from list",
			didDocFileName: "diddocument_with_list_of_did.json",
			kid:            "#vm-1",
			expectedKey: &verifiable.CommonVerificationMethod{
				ID:         "#vm-1",
				Controller: "did:test:1",
				Type:       "EcdsaSecp256k1VerificationKey2019",
				PublicKeyJwk: map[string]interface{}{
					"testID": "5",
					"kty":    "EC",
					"crv":    "secp256k1",
					"x":      "WfY7Px6AgH6x-_dgAoRbg8weYRJA36ON-gQiFnETrqw",
					"y":      "IzFx3BUGztK0cyDStiunXbrZYYTtKbOUzx16SUK0sAY",
				},
			},
		},
		{
			name:           "More priority vm should be from authentication section",
			didDocFileName: "diddocument_with_list_of_did.json",
			kid:            "", // empty kid
			expectedKey: &verifiable.CommonVerificationMethod{
				ID:         "#vm-1",
				Controller: "did:test:1",
				Type:       "EcdsaSecp256k1VerificationKey2019",
				PublicKeyJwk: map[string]interface{}{
					"testID": "5",
					"kty":    "EC",
					"crv":    "secp256k1",
					"x":      "WfY7Px6AgH6x-_dgAoRbg8weYRJA36ON-gQiFnETrqw",
					"y":      "IzFx3BUGztK0cyDStiunXbrZYYTtKbOUzx16SUK0sAY",
				},
			},
		},
		{
			name:           "Vm in auth section",
			didDocFileName: "diddocument_with_wm_on_authentication_section.json",
			kid:            "#vm-2",
			expectedKey: &verifiable.CommonVerificationMethod{
				ID:         "#vm-2",
				Controller: "did:test:2",
				Type:       "EcdsaSecp256k1VerificationKey2019",
				PublicKeyJwk: map[string]interface{}{
					"testID": "10",
					"kty":    "EC",
					"crv":    "secp256k1",
					"x":      "WfY7Px6AgH6x-_dgAoRbg8weYRJA36ON-gQiFnETrqw",
					"y":      "IzFx3BUGztK0cyDStiunXbrZYYTtKbOUzx16SUK0sAY",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			didDoc, err := loadDIDDoc(tt.didDocFileName)
			require.NoError(t, err)
			key, err := lookForKid(didDoc, tt.kid)
			require.NoError(t, err)
			require.Equal(t, tt.expectedKey, key)
		})
	}
}
func loadDIDDoc(fileName string) (*verifiable.DIDDocument, error) {
	file, err := os.Open(fmt.Sprintf("testdata/jws/%s", fileName))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// decode json
	didDoc := &verifiable.DIDDocument{}
	err = json.NewDecoder(file).Decode(didDoc)
	if err != nil {
		return nil, err
	}

	return didDoc, nil
}

func setupJWSPacker() *JWSPacker {
	didResolverHandler := func(did string) (*verifiable.DIDDocument, error) {
		var doc verifiable.DIDDocument
		_ = json.Unmarshal([]byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2",{"esrs2020":"https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","privateKeyJwk":{"@id":"esrs2020:privateKeyJwk","@type":"@json"},"publicKeyHex":"esrs2020:publicKeyHex","privateKeyHex":"esrs2020:privateKeyHex","ethereumAddress":"esrs2020:ethereumAddress"}],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#vm-1","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw","kty":"EC","x":"_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk","y":"Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc"}}],"authentication":["did:example:123#vm-1"]}`), &doc)
		return &doc, nil
	}

	opaqueSignerResolverHandlerFunc := func(kid string) (jose.OpaqueSigner, error) {
		return &OpaqueSignerMock{}, nil
	}

	opaqueVerifierResolverHandlerFunc := func(vm *verifiable.CommonVerificationMethod) (jose.OpaqueVerifier, error) {
		return &OpaqueVerifierMock{}, nil
	}

	return NewJWSPacker(
		didResolverHandler,
		opaqueSignerResolverHandlerFunc,
		opaqueVerifierResolverHandlerFunc,
	)
}
