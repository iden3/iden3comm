package packers

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2/packers/providers/bjj"
	"github.com/iden3/iden3comm/v2/packers/providers/es256k"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/require"
)

const exampleDidDoc = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2"],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#vm-1","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","kty":"EC","x":"YEwwxb2s2kjvKodwoW3II8JhcvYk-51hD74Kkq63syc=","y":"fCIyEltvzDs0JZnL25-YyyDgLrbZTw9y3lM2BLDhQbU="}}],"authentication":["did:example:123#vm-1"]}`
const exampleDidDocJS = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2"],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#vm-1","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","kty":"EC","x":"_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk","y":"Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc"}}],"authentication":["did:example:123#vm-1"]}`

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
			return es256k.PrivateKeyFromHex(
				"8104d697aa619dd4df4b80df650d4eca0c63fcc2a423c151112aefd562122e55")
		}),
	}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	token, err := p.Pack(
		msgBytes,
		SigningParams{
			SenderDIDstr: `did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29`,
			Alg:          jwa.ES256K,
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
						ID:         "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29",
						Type:       string(EddsaBJJVerificationKey),
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
			return bjj.GoSignerFromPrivHex(
				"d115b0481a020428b5de28196513e1b28aa0475c0ac064d73243321cd7b9200c")
		}),
	}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	token, err := p.Pack(
		msgBytes,
		SigningParams{
			SenderDIDstr: `did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29`,
			Alg:          bjj.Alg,
		})
	require.NoError(t, err)

	_, err = p.Unpack(token)
	require.NoError(t, err)
}

func TestJWS(t *testing.T) {
	// token from js impelementation
	const token = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6eDRqY0hQNFhIVEszdlg1OEFIWlB5SEU4a1lqbmV5RTZGWlJmejdLMjkiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tc2lnbmVkLWpzb24ifQ.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp4NGpjSFA0WEhUSzN2WDU4QUhaUHlIRThrWWpuZXlFNkZaUmZ6N0syOSIsImJvZHkiOnsic2NvcGUiOlt7InR5cGUiOiJ6ZXJva25vd2xlZGdlIiwiY2lyY3VpdF9pZCI6ImF1dGgiLCJwdWJfc2lnbmFscyI6WyIxIiwiMTgzMTE1NjA1MjUzODMzMTk3MTkzMTEzOTQ5NTcwNjQ4MjAwOTEzNTQ5NzYzMTA1OTk4MTg3OTcxNTcxODk1Njg2MjE0NjY5NTA4MTEiLCIzMjM0MTY5MjUyNjQ2NjYyMTc2MTcyODg1Njk3NDI1NjQ3MDM2MzI4NTA4MTYwMzU3NjEwODQwMDI3MjAwOTAzNzczNTMyOTc5MjAiXSwicHJvb2ZfZGF0YSI6eyJwaV9hIjpbIjExMTMwODQzMTUwNTQwNzg5Mjk5NDU4OTkwNTg2MDIwMDAwNzE5MjgwMjQ2MTUzNzk3ODgyODQzMjE0MjkwNTQxOTgwNTIyMzc1MDcyIiwiMTMwMDg0MTkxMjk0Mzc4MTcyMzAyMjAzMjM1NTgzNjg5MzgzMTEzMjkyMDc4Mzc4ODQ1NTUzMTgzODI1NDQ2NTc4NDYwNTc2MjcxMyIsIjEiXSwicGlfYiI6W1siMjA2MTU3Njg1MzY5ODg0MzgzMzY1Mzc3Nzc5MDkwNDIzNTIwNTYzOTI4NjIyNTE3ODU3MjI3OTY2Mzc1OTAyMTIxNjA1NjEzNTE2NTYiLCIxMDM3MTE0NDgwNjEwNzc3ODg5MDUzODg1NzcwMDg1NTEwODY2NzYyMjA0MjIxNTA5Njk3MTc0NzIwMzEwNTk5NzQ1NDYyNTgxNDA4MCJdLFsiMTk1OTg1NDEzNTA4MDQ0Nzg1NDkxNDEyMDc4MzUwMjg2NzExMTEwNjM5MTU2MzU1ODA2Nzk2OTQ5MDc2MzU5MTQyNzk5Mjg2Nzc4MTIiLCIxNTI2NDU1MzA0NTUxNzA2NTY2OTE3MTU4NDk0Mzk2NDMyMjExNzM5NzY0NTE0NzAwNjkwOTE2NzQyNzgwOTgzNzkyOTQ1ODAxMjkxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTY0NDMzMDkyNzk4MjU1MDg4OTMwODYyNTEyOTAwMDM5MzY5MzUwNzczNDg3NTQwOTc0NzA4MTg1MjM1NTgwODI1MDIzNjQ4MjIwNDkiLCIyOTg0MTgwMjI3NzY2MDQ4MTAwNTEwMTIwNDA3MTUwNzUyMDUyMzM0NTcxODc2NjgxMzA0OTk5NTk1NTQ0MTM4MTU1NjExOTYzMjczIiwiMSJdLCJwcm90b2NvbCI6IiJ9fV19fQ.w8cIb4XyguxRU73Tp3VB3sZh3P00y52tnpTiuTkZQkbYKiOhecpMSpJZ16u4qE8oQIsfNwY34SYgSZ88dyQbcA`
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

func TestJWSBlockChainAccountId(t *testing.T) {
	// token from js impelementation
	const token = `eyJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDpwa2g6cG9seToweDcxNDFFNGQyMEY3NjQ0REM4YzBBZENBOGE1MjBFQzgzQzZjQUJENjUjUmVjb3ZlcnkyMDIwIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXNpZ25lZC1qc29uIn0.eyJpZCI6IjA3ZWRhYzM2LWFlZmYtNGVhMy04ZWY2LWI4Nzk4ODk3NzVhMiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJ0aGlkIjoiZmI3YWQ1ZDItNWI1MC00NWRhLThiODAtNzMxNzFlMjE3Zjc0IiwiYm9keSI6eyJzY29wZSI6W119LCJmcm9tIjoiZGlkOnBraDpwb2x5OjB4NzE0MUU0ZDIwRjc2NDREQzhjMEFkQ0E4YTUyMEVDODNDNmNBQkQ2NSNSZWNvdmVyeTIwMjAiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIn0.uK2bpgdZJV_doN-O49335oi3mzVFY_sji_Ze7-y7soHa_f34HjXhdQF0NbQiJ50Ih2m9MFSkTk8rs2ruXnZ-dgA`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(`{
				"@context": [
				  "https://www.w3.org/ns/did/v1",
				  {
					"EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
					"blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
				  }
				],
				"id": "did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65",
				"verificationMethod": [
				  {
					"id": "did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020",
					"type": "EcdsaSecp256k1RecoveryMethod2020",
					"controller": "did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65",
					"blockchainAccountId": "eip155:137:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65"
				  }
				],
				"authentication": [
				  "did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020"
				],
				"assertionMethod": [
				  "did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020"
				]
			  }`), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),
	}

	_, err := p.Unpack([]byte(token))
	require.NoError(t, err)
}

func TestJWS_InvalidCase(t *testing.T) {
	const token = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6eDRqY0hQNFhIVEszdlg1OEFIWlB5SEU4a1lqbmV5RTZGWlJmejdLMjkiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tc2lnbmVkLWpzb24ifQ.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp4NGpjSFA0WEhUSzN2WDU4QUhaUHlIRThrWWpuZXlFNkZaUmZ6N0syOSIsImJvZHkiOnsic2NvcGUiOlt7InR5cGUiOiJ6ZXJva25vd2xlZGdlIiwiY2lyY3VpdF9pZCI6ImF1dGgiLCJwdWJfc2lnbmFscyI6WyIxIiwiMTgzMTE1NjA1MjUzODMzMTk3MTkzMTEzOTQ5NTcwNjQ4MjAwOTEzNTQ5NzYzMTA1OTk4MTg3OTcxNTcxODk1Njg2MjE0NjY5NTA4MTEiLCIzMjM0MTY5MjUyNjQ2NjYyMTc2MTcyODg1Njk3NDI1NjQ3MDM2MzI4NTA4MTYwMzU3NjEwODQwMDI3MjAwOTAzNzczNTMyOTc5MjAiXSwicHJvb2ZfZGF0YSI6eyJwaV9hIjpbIjExMTMwODQzMTUwNTQwNzg5Mjk5NDU4OTkwNTg2MDIwMDAwNzE5MjgwMjQ2MTUzNzk3ODgyODQzMjE0MjkwNTQxOTgwNTIyMzc1MDcyIiwiMTMwMDg0MTkxMjk0Mzc4MTcyMzAyMjAzMjM1NTgzNjg5MzgzMTEzMjkyMDc4Mzc4ODQ1NTUzMTgzODI1NDQ2NTc4NDYwNTc2MjcxMyIsIjEiXSwicGlfYiI6W1siMjA2MTU3Njg1MzY5ODg0MzgzMzY1Mzc3Nzc5MDkwNDIzNTIwNTYzOTI4NjIyNTE3ODU3MjI3OTY2Mzc1OTAyMTIxNjA1NjEzNTE2NTYiLCIxMDM3MTE0NDgwNjEwNzc3ODg5MDUzODg1NzcwMDg1NTEwODY2NzYyMjA0MjIxNTA5Njk3MTc0NzIwMzEwNTk5NzQ1NDYyNTgxNDA4MCJdLFsiMTk1OTg1NDEzNTA4MDQ0Nzg1NDkxNDEyMDc4MzUwMjg2NzExMTEwNjM5MTU2MzU1ODA2Nzk2OTQ5MDc2MzU5MTQyNzk5Mjg2Nzc4MTIiLCIxNTI2NDU1MzA0NTUxNzA2NTY2OTE3MTU4NDk0Mzk2NDMyMjExNzM5NzY0NTE0NzAwNjkwOTE2NzQyNzgwOTgzNzkyOTQ1ODAxMjkxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTY0NDMzMDkyNzk4MjU1MDg4OTMwODYyNTEyOTAwMDM5MzY5MzUwNzczNDg3NTQwOTc0NzA4MTg1MjM1NTgwODI1MDIzNjQ4MjIwNDkiLCIyOTg0MTgwMjI3NzY2MDQ4MTAwNTEwMTIwNDA3MTUwNzUyMDUyMzM0NTcxODc2NjgxMzA0OTk5NTk1NTQ0MTM4MTU1NjExOTYzMjczIiwiMSJdLCJwcm90b2NvbCI6IiJ9fV19fQ.b8cIb4XyguxRU73Tp3VB3sZh3P00y52tnpTiuTkZQkbYKiOhecpMSpJZ16u4qE8oQIsfNwY34SYgSZ88dyQbcM`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(exampleDidDocJS), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),
	}

	_, err := p.Unpack([]byte(token))
	require.ErrorContains(t, err,
		"could not verify message using any of the signatures or keys")
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
