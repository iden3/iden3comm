package packers

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	bjj "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/require"
)

type BjjSignWrapper struct {
	pk *bjj.PrivateKey
}

func (s *BjjSignWrapper) Public() crypto.PublicKey {
	return nil
}

func (s *BjjSignWrapper) Sign(_ io.Reader, buf []byte, _ crypto.SignerOpts) ([]byte, error) {
	digest := big.NewInt(0).SetBytes(buf)
	compressed := s.pk.SignPoseidon(digest).Compress()

	sig, err := compressed.MarshalText()
	if err != nil {
		return nil, err
	}
	return sig, nil
}

const exampleDidDoc = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2"],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#vm-1","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw","kty":"EC","x":"YEwwxb2s2kjvKodwoW3II8JhcvYk-51hD74Kkq63syc=","y":"fCIyEltvzDs0JZnL25-YyyDgLrbZTw9y3lM2BLDhQbU="}}],"authentication":["did:example:123#vm-1"]}`
const exampleDidDocJS = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2"],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#vm-1","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw","kty":"EC","x":"_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk","y":"Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc"}}],"authentication":["did:example:123#vm-1"]}`

// add kid for select key
func TestPKHKey(t *testing.T) {
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(exampleDidDoc), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),

		signerResolverHandlerFunc: SignerResolverHandlerFunc(func(kid string) (crypto.Signer, error) {
			D, _ := big.NewInt(0).SetString(
				"58356905918113884252537723315263545219814949716680947267522788415477306764885", 10,
			)

			pk := &ecdsa.PrivateKey{
				D: D,
				PublicKey: ecdsa.PublicKey{
					Curve: secp256k1.S256(),
				},
			}

			return pk, nil
		}),
	}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	token, err := p.Pack(
		msgBytes,
		SigningParams{
			SenderDID: `did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29`,
			Alg:       jwa.ES256,
		})
	require.NoError(t, err)

	_, err = p.Unpack(token)
	require.NoError(t, err)
}

func TestBJJKey(t *testing.T) {
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
			return &verifiable.DIDDocument{
				Context: []string{
					"https://www.w3.org/ns/did/v1",
				},
				VerificationMethod: []verifiable.CommonVerificationMethod{
					{
						ID:         "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#key-1",
						Type:       "EddsaBN256VerificaonKey",
						Controller: "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29",
						PublicKeyJwk: map[string]interface{}{
							"kty": "EC",
							"crv": "BJJ",
							"x":   "Iunwi3h0Y34DT8zAvKKSt_QrMkL9d3Ow0XygV253UfE=",
							"y":   "CvilGVOsA_Fsq9IeGFYI2jkRKCcnWO_z9MtaOhN9PNc=",
						},
					},
				},
			}, nil
		}),

		signerResolverHandlerFunc: SignerResolverHandlerFunc(func(kid string) (crypto.Signer, error) {
			rawPK, err := hex.DecodeString("d115b0481a020428b5de28196513e1b28aa0475c0ac064d73243321cd7b9200c")
			if err != nil {
				return nil, err
			}

			var pk bjj.PrivateKey
			copy(pk[:], rawPK)

			return &BjjSignWrapper{&pk}, nil
		}),
	}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	token, err := p.Pack(
		msgBytes,
		SigningParams{
			SenderDID: `did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29`,
			Alg:       BJJAlg,
		})
	require.NoError(t, err)

	_, err = p.Unpack(token)
	require.NoError(t, err)
}

func TestJWS(t *testing.T) {
	// token from js impelementation
	const token = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZToxMjMjdm0tMSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiJ9.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDpleGFtcGxlOjEyMyIsImJvZHkiOnsic2NvcGUiOlt7InR5cGUiOiJ6ZXJva25vd2xlZGdlIiwiY2lyY3VpdF9pZCI6ImF1dGgiLCJwdWJfc2lnbmFscyI6WyIxIiwiMTgzMTE1NjA1MjUzODMzMTk3MTkzMTEzOTQ5NTcwNjQ4MjAwOTEzNTQ5NzYzMTA1OTk4MTg3OTcxNTcxODk1Njg2MjE0NjY5NTA4MTEiLCIzMjM0MTY5MjUyNjQ2NjYyMTc2MTcyODg1Njk3NDI1NjQ3MDM2MzI4NTA4MTYwMzU3NjEwODQwMDI3MjAwOTAzNzczNTMyOTc5MjAiXSwicHJvb2ZfZGF0YSI6eyJwaV9hIjpbIjExMTMwODQzMTUwNTQwNzg5Mjk5NDU4OTkwNTg2MDIwMDAwNzE5MjgwMjQ2MTUzNzk3ODgyODQzMjE0MjkwNTQxOTgwNTIyMzc1MDcyIiwiMTMwMDg0MTkxMjk0Mzc4MTcyMzAyMjAzMjM1NTgzNjg5MzgzMTEzMjkyMDc4Mzc4ODQ1NTUzMTgzODI1NDQ2NTc4NDYwNTc2MjcxMyIsIjEiXSwicGlfYiI6W1siMjA2MTU3Njg1MzY5ODg0MzgzMzY1Mzc3Nzc5MDkwNDIzNTIwNTYzOTI4NjIyNTE3ODU3MjI3OTY2Mzc1OTAyMTIxNjA1NjEzNTE2NTYiLCIxMDM3MTE0NDgwNjEwNzc3ODg5MDUzODg1NzcwMDg1NTEwODY2NzYyMjA0MjIxNTA5Njk3MTc0NzIwMzEwNTk5NzQ1NDYyNTgxNDA4MCJdLFsiMTk1OTg1NDEzNTA4MDQ0Nzg1NDkxNDEyMDc4MzUwMjg2NzExMTEwNjM5MTU2MzU1ODA2Nzk2OTQ5MDc2MzU5MTQyNzk5Mjg2Nzc4MTIiLCIxNTI2NDU1MzA0NTUxNzA2NTY2OTE3MTU4NDk0Mzk2NDMyMjExNzM5NzY0NTE0NzAwNjkwOTE2NzQyNzgwOTgzNzkyOTQ1ODAxMjkxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTY0NDMzMDkyNzk4MjU1MDg4OTMwODYyNTEyOTAwMDM5MzY5MzUwNzczNDg3NTQwOTc0NzA4MTg1MjM1NTgwODI1MDIzNjQ4MjIwNDkiLCIyOTg0MTgwMjI3NzY2MDQ4MTAwNTEwMTIwNDA3MTUwNzUyMDUyMzM0NTcxODc2NjgxMzA0OTk5NTk1NTQ0MTM4MTU1NjExOTYzMjczIiwiMSJdLCJwcm90b2NvbCI6IiJ9fV19fQ.de_qaDM7VYFaPUCNDGsvwF04tT4S4nXBO8dqXnU8XAof0Uip5LDCe4-IjEBPxu0sLh8BxcvPHMYMjx_pvPcqWw`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(exampleDidDocJS), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),
	}

	_, err := p.Unpack([]byte(token))
	require.NoError(t, err)
}

func TestLookForKid(t *testing.T) {
	tests := []struct {
		name           string
		didDocFileName string
		kid            string
		expectedKey    verifiable.CommonVerificationMethod
	}{
		{
			name:           "Try to find vm by did",
			didDocFileName: "diddocument_with_jws_did.json",
			kid:            "#vm-1",
			expectedKey: verifiable.CommonVerificationMethod{
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
			expectedKey: verifiable.CommonVerificationMethod{
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
			expectedKey: verifiable.CommonVerificationMethod{
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
			expectedKey: verifiable.CommonVerificationMethod{
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
			expectedKey: verifiable.CommonVerificationMethod{
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
			key, err := lookupForKid(didDoc, tt.kid)
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
