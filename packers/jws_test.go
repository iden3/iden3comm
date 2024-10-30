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

const exampleDidDoc = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2"],"id":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","verificationMethod":[{"id":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#vm-1","controller":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw","kty":"EC","x":"YEwwxb2s2kjvKodwoW3II8JhcvYk-51hD74Kkq63syc=","y":"fCIyEltvzDs0JZnL25-YyyDgLrbZTw9y3lM2BLDhQbU="}}],"authentication":["did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#vm-1"]}`
const exampleDidDocJS = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2",{"esrs2020":"https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","privateKeyJwk":{"@id":"esrs2020:privateKeyJwk","@type":"@json"},"publicKeyHex":"esrs2020:publicKeyHex","privateKeyHex":"esrs2020:privateKeyHex","ethereumAddress":"esrs2020:ethereumAddress"}],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw","kty":"EC","x":"_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk","y":"Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc"}}],"authentication":["did:example:123#JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"]}`

// add kid for select key
func TestPKHKey(t *testing.T) {
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(exampleDidDoc), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),

		signerResolverHandlerFunc: SignerResolverHandlerFunc(func(_ string) (crypto.Signer, error) {
			return es256k.PrivateKeyFromHex(
				"8104d697aa619dd4df4b80df650d4eca0c63fcc2a423c151112aefd562122e55")
		}),
	}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	token, err := p.Pack(
		msgBytes,
		SigningParams{
			Alg: jwa.ES256K,
		})
	require.NoError(t, err)

	_, err = p.Unpack(token)
	require.NoError(t, err)
}

func TestBJJKey(t *testing.T) {
	auth := &verifiable.Authentication{}
	err := auth.UnmarshalJSON([]byte("\"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#key-1\""))
	require.NoError(t, err)
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
			return &verifiable.DIDDocument{
				Context: []string{
					"https://www.w3.org/ns/did/v1",
				},
				VerificationMethod: []verifiable.CommonVerificationMethod{
					{
						ID:         "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#key-1",
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
				Authentication: []verifiable.Authentication{*auth},
			}, nil
		}),

		signerResolverHandlerFunc: SignerResolverHandlerFunc(func(_ string) (crypto.Signer, error) {
			return bjj.GoSignerFromPrivHex(
				"d115b0481a020428b5de28196513e1b28aa0475c0ac064d73243321cd7b9200c")
		}),
	}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	token, err := p.Pack(
		msgBytes,
		SigningParams{
			Alg: bjj.Alg,
			KID: "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29#key-1",
		})
	require.NoError(t, err)

	_, err = p.Unpack(token)
	require.NoError(t, err)
}

func TestJWS(t *testing.T) {
	// token from js impelementation
	const token = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZToxMjMjSlV2cGxsTUVZVVoyam9PNTlVTnVpX1hZRHF4VnFpRkxMQUo4a2xXdVBCdyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiJ9.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDpleGFtcGxlOjEyMyIsImJvZHkiOnsic2NvcGUiOlt7InR5cGUiOiJ6ZXJva25vd2xlZGdlIiwiY2lyY3VpdF9pZCI6ImF1dGgiLCJwdWJfc2lnbmFscyI6WyIxIiwiMTgzMTE1NjA1MjUzODMzMTk3MTkzMTEzOTQ5NTcwNjQ4MjAwOTEzNTQ5NzYzMTA1OTk4MTg3OTcxNTcxODk1Njg2MjE0NjY5NTA4MTEiLCIzMjM0MTY5MjUyNjQ2NjYyMTc2MTcyODg1Njk3NDI1NjQ3MDM2MzI4NTA4MTYwMzU3NjEwODQwMDI3MjAwOTAzNzczNTMyOTc5MjAiXSwicHJvb2ZfZGF0YSI6eyJwaV9hIjpbIjExMTMwODQzMTUwNTQwNzg5Mjk5NDU4OTkwNTg2MDIwMDAwNzE5MjgwMjQ2MTUzNzk3ODgyODQzMjE0MjkwNTQxOTgwNTIyMzc1MDcyIiwiMTMwMDg0MTkxMjk0Mzc4MTcyMzAyMjAzMjM1NTgzNjg5MzgzMTEzMjkyMDc4Mzc4ODQ1NTUzMTgzODI1NDQ2NTc4NDYwNTc2MjcxMyIsIjEiXSwicGlfYiI6W1siMjA2MTU3Njg1MzY5ODg0MzgzMzY1Mzc3Nzc5MDkwNDIzNTIwNTYzOTI4NjIyNTE3ODU3MjI3OTY2Mzc1OTAyMTIxNjA1NjEzNTE2NTYiLCIxMDM3MTE0NDgwNjEwNzc3ODg5MDUzODg1NzcwMDg1NTEwODY2NzYyMjA0MjIxNTA5Njk3MTc0NzIwMzEwNTk5NzQ1NDYyNTgxNDA4MCJdLFsiMTk1OTg1NDEzNTA4MDQ0Nzg1NDkxNDEyMDc4MzUwMjg2NzExMTEwNjM5MTU2MzU1ODA2Nzk2OTQ5MDc2MzU5MTQyNzk5Mjg2Nzc4MTIiLCIxNTI2NDU1MzA0NTUxNzA2NTY2OTE3MTU4NDk0Mzk2NDMyMjExNzM5NzY0NTE0NzAwNjkwOTE2NzQyNzgwOTgzNzkyOTQ1ODAxMjkxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTY0NDMzMDkyNzk4MjU1MDg4OTMwODYyNTEyOTAwMDM5MzY5MzUwNzczNDg3NTQwOTc0NzA4MTg1MjM1NTgwODI1MDIzNjQ4MjIwNDkiLCIyOTg0MTgwMjI3NzY2MDQ4MTAwNTEwMTIwNDA3MTUwNzUyMDUyMzM0NTcxODc2NjgxMzA0OTk5NTk1NTQ0MTM4MTU1NjExOTYzMjczIiwiMSJdLCJwcm90b2NvbCI6IiJ9fV19fQ._p8wS2JZELczn33_uB6EfmXzZ3RaizJVZIEclTT_UWS-xtPR6jpcthmRZGU1yrBQCNsf2ScWqvzzAV3DOJuKsg`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(exampleDidDocJS), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),
	}

	_, err := p.Unpack([]byte(token))
	require.NoError(t, err)
}

func TestES256K_JWS_WithRecoveryFalse(t *testing.T) {
	// token from js impelementation
	const token = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aWRlbjM6cHJpdmFkbzptYWluOjJTWkRzZFlvcmRTSDQ5VmhTNmhHbzE2NFJMd2ZjUWU5RkdvdzVmdFNVRyN2bS0xIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXNpZ25lZC1qc29uIn0.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwcml2YWRvOm1haW46MlNaRHNkWW9yZFNINDlWaFM2aEdvMTY0Ukx3ZmNRZTlGR293NWZ0U1VHIiwiYm9keSI6eyJzY29wZSI6W3sidHlwZSI6Inplcm9rbm93bGVkZ2UiLCJjaXJjdWl0X2lkIjoiYXV0aCIsInB1Yl9zaWduYWxzIjpbIjEiLCIxODMxMTU2MDUyNTM4MzMxOTcxOTMxMTM5NDk1NzA2NDgyMDA5MTM1NDk3NjMxMDU5OTgxODc5NzE1NzE4OTU2ODYyMTQ2Njk1MDgxMSIsIjMyMzQxNjkyNTI2NDY2NjIxNzYxNzI4ODU2OTc0MjU2NDcwMzYzMjg1MDgxNjAzNTc2MTA4NDAwMjcyMDA5MDM3NzM1MzI5NzkyMCJdLCJwcm9vZl9kYXRhIjp7InBpX2EiOlsiMTExMzA4NDMxNTA1NDA3ODkyOTk0NTg5OTA1ODYwMjAwMDA3MTkyODAyNDYxNTM3OTc4ODI4NDMyMTQyOTA1NDE5ODA1MjIzNzUwNzIiLCIxMzAwODQxOTEyOTQzNzgxNzIzMDIyMDMyMzU1ODM2ODkzODMxMTMyOTIwNzgzNzg4NDU1NTMxODM4MjU0NDY1Nzg0NjA1NzYyNzEzIiwiMSJdLCJwaV9iIjpbWyIyMDYxNTc2ODUzNjk4ODQzODMzNjUzNzc3NzkwOTA0MjM1MjA1NjM5Mjg2MjI1MTc4NTcyMjc5NjYzNzU5MDIxMjE2MDU2MTM1MTY1NiIsIjEwMzcxMTQ0ODA2MTA3Nzc4ODkwNTM4ODU3NzAwODU1MTA4NjY3NjIyMDQyMjE1MDk2OTcxNzQ3MjAzMTA1OTk3NDU0NjI1ODE0MDgwIl0sWyIxOTU5ODU0MTM1MDgwNDQ3ODU0OTE0MTIwNzgzNTAyODY3MTExMTA2MzkxNTYzNTU4MDY3OTY5NDkwNzYzNTkxNDI3OTkyODY3NzgxMiIsIjE1MjY0NTUzMDQ1NTE3MDY1NjY5MTcxNTg0OTQzOTY0MzIyMTE3Mzk3NjQ1MTQ3MDA2OTA5MTY3NDI3ODA5ODM3OTI5NDU4MDEyOTEzIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjQ0MzMwOTI3OTgyNTUwODg5MzA4NjI1MTI5MDAwMzkzNjkzNTA3NzM0ODc1NDA5NzQ3MDgxODUyMzU1ODA4MjUwMjM2NDgyMjA0OSIsIjI5ODQxODAyMjc3NjYwNDgxMDA1MTAxMjA0MDcxNTA3NTIwNTIzMzQ1NzE4NzY2ODEzMDQ5OTk1OTU1NDQxMzgxNTU2MTE5NjMyNzMiLCIxIl0sInByb3RvY29sIjoiIn19XX19.pJW9lqTRBXcXWhiZkEcrFlUqSAunX6He-wmEW_J6zEhgRVz14LkC5XhVcrWleqTB57j0tcAgaeSAdgJkRSkshw`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
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
	const token = `eyJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDpwa2g6cG9seToweEIwNjEyNjg2RThENDlDYTQ1MzkyODkzYTk3N0RlNTRiRkEyOTM1QzcjUmVjb3ZlcnkyMDIwIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXNpZ25lZC1qc29uIn0.eyJpZCI6IjM5MWQyYjlhLTk5MTktNGYzMi04OTJlLTRkYTNlZDg3N2ZkYSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJ0aGlkIjoiZmI3YWQ1ZDItNWI1MC00NWRhLThiODAtNzMxNzFlMjE3Zjc0IiwiYm9keSI6eyJzY29wZSI6W119LCJmcm9tIjoiZGlkOnBraDpwb2x5OjB4QjA2MTI2ODZFOEQ0OUNhNDUzOTI4OTNhOTc3RGU1NGJGQTI5MzVDNyIsInRvIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUo2ODlrcG9KeGNTekI1c0FGSnRQc1NCU3JIRjVkcTcyMkJITXFVUkwifQ.X9YSNYYrt21Duft6R0hY6PKJodHdCpY_8XxydCLHCRBTXhsUWkF4dkPv8Mcvg-XsAD7dBpwY8aAPqCL9qq_JhwA`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(`{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
      "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
    }
  ],
  "id": "did:pkh:poly:0xB0612686E8D49Ca45392893a977De54bFA2935C7",
  "verificationMethod": [
    {
      "id": "did:pkh:poly:0xB0612686E8D49Ca45392893a977De54bFA2935C7#Recovery2020",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:pkh:poly:0xB0612686E8D49Ca45392893a977De54bFA2935C7",
      "blockchainAccountId": "eip155:137:0xB0612686E8D49Ca45392893a977De54bFA2935C7"
    }
  ],
  "authentication": [
    "did:pkh:poly:0xB0612686E8D49Ca45392893a977De54bFA2935C7#Recovery2020"
  ],
  "assertionMethod": [
    "did:pkh:poly:0xB0612686E8D49Ca45392893a977De54bFA2935C7#Recovery2020"
  ]
}`), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),
	}

	_, err := p.Unpack([]byte(token))
	require.NoError(t, err)
}

func TestES256K_RecoverableFalse(t *testing.T) {
	// token from js impelementation - ES256K recoverable false (signature length = 64)
	const token = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aWRlbjM6cHJpdmFkbzptYWluOjJTWkRzZFlvcmRTSDQ5VmhTNmhHbzE2NFJMd2ZjUWU5RkdvdzVmdFNVRyN2bS0xIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXNpZ25lZC1qc29uIn0.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwcml2YWRvOm1haW46MlNaRHNkWW9yZFNINDlWaFM2aEdvMTY0Ukx3ZmNRZTlGR293NWZ0U1VHIiwiYm9keSI6eyJzY29wZSI6W3sidHlwZSI6Inplcm9rbm93bGVkZ2UiLCJjaXJjdWl0X2lkIjoiYXV0aCIsInB1Yl9zaWduYWxzIjpbIjEiLCIxODMxMTU2MDUyNTM4MzMxOTcxOTMxMTM5NDk1NzA2NDgyMDA5MTM1NDk3NjMxMDU5OTgxODc5NzE1NzE4OTU2ODYyMTQ2Njk1MDgxMSIsIjMyMzQxNjkyNTI2NDY2NjIxNzYxNzI4ODU2OTc0MjU2NDcwMzYzMjg1MDgxNjAzNTc2MTA4NDAwMjcyMDA5MDM3NzM1MzI5NzkyMCJdLCJwcm9vZl9kYXRhIjp7InBpX2EiOlsiMTExMzA4NDMxNTA1NDA3ODkyOTk0NTg5OTA1ODYwMjAwMDA3MTkyODAyNDYxNTM3OTc4ODI4NDMyMTQyOTA1NDE5ODA1MjIzNzUwNzIiLCIxMzAwODQxOTEyOTQzNzgxNzIzMDIyMDMyMzU1ODM2ODkzODMxMTMyOTIwNzgzNzg4NDU1NTMxODM4MjU0NDY1Nzg0NjA1NzYyNzEzIiwiMSJdLCJwaV9iIjpbWyIyMDYxNTc2ODUzNjk4ODQzODMzNjUzNzc3NzkwOTA0MjM1MjA1NjM5Mjg2MjI1MTc4NTcyMjc5NjYzNzU5MDIxMjE2MDU2MTM1MTY1NiIsIjEwMzcxMTQ0ODA2MTA3Nzc4ODkwNTM4ODU3NzAwODU1MTA4NjY3NjIyMDQyMjE1MDk2OTcxNzQ3MjAzMTA1OTk3NDU0NjI1ODE0MDgwIl0sWyIxOTU5ODU0MTM1MDgwNDQ3ODU0OTE0MTIwNzgzNTAyODY3MTExMTA2MzkxNTYzNTU4MDY3OTY5NDkwNzYzNTkxNDI3OTkyODY3NzgxMiIsIjE1MjY0NTUzMDQ1NTE3MDY1NjY5MTcxNTg0OTQzOTY0MzIyMTE3Mzk3NjQ1MTQ3MDA2OTA5MTY3NDI3ODA5ODM3OTI5NDU4MDEyOTEzIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjQ0MzMwOTI3OTgyNTUwODg5MzA4NjI1MTI5MDAwMzkzNjkzNTA3NzM0ODc1NDA5NzQ3MDgxODUyMzU1ODA4MjUwMjM2NDgyMjA0OSIsIjI5ODQxODAyMjc3NjYwNDgxMDA1MTAxMjA0MDcxNTA3NTIwNTIzMzQ1NzE4NzY2ODEzMDQ5OTk1OTU1NDQxMzgxNTU2MTE5NjMyNzMiLCIxIl0sInByb3RvY29sIjoiIn19XX19.pJW9lqTRBXcXWhiZkEcrFlUqSAunX6He-wmEW_J6zEhgRVz14LkC5XhVcrWleqTB57j0tcAgaeSAdgJkRSkshw`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(`{
					"@context": [
						"https://www.w3.org/ns/did/v1",
						"https://w3id.org/security/suites/secp256k1recovery-2020/v2"
					],
					"id": "did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG",
					"verificationMethod": [
					{
						"id": "did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG#vm-1",
						"controller": "did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG",
						"type": "EcdsaSecp256k1RecoveryMethod2020",
						"blockchainAccountId": "eip155:21000:0x964e496a1b2541ed029abd5e49fd01e41cd02995"
					}
					],
					"authentication": ["did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG#vm-1"]
					}`), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),
	}

	_, err := p.Unpack([]byte(token))
	require.NoError(t, err)
}

func TestES256K_R_RecoverableFalse(t *testing.T) {
	// token from js impelementation - ES256K-R recoverable false (signature length = 64)
	const token = `eyJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDppZGVuMzpwcml2YWRvOm1haW46MlNaRHNkWW9yZFNINDlWaFM2aEdvMTY0Ukx3ZmNRZTlGR293NWZ0U1VHI3ZtLTEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tc2lnbmVkLWpzb24ifQ.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwcml2YWRvOm1haW46MlNaRHNkWW9yZFNINDlWaFM2aEdvMTY0Ukx3ZmNRZTlGR293NWZ0U1VHIiwiYm9keSI6eyJzY29wZSI6W3sidHlwZSI6Inplcm9rbm93bGVkZ2UiLCJjaXJjdWl0X2lkIjoiYXV0aCIsInB1Yl9zaWduYWxzIjpbIjEiLCIxODMxMTU2MDUyNTM4MzMxOTcxOTMxMTM5NDk1NzA2NDgyMDA5MTM1NDk3NjMxMDU5OTgxODc5NzE1NzE4OTU2ODYyMTQ2Njk1MDgxMSIsIjMyMzQxNjkyNTI2NDY2NjIxNzYxNzI4ODU2OTc0MjU2NDcwMzYzMjg1MDgxNjAzNTc2MTA4NDAwMjcyMDA5MDM3NzM1MzI5NzkyMCJdLCJwcm9vZl9kYXRhIjp7InBpX2EiOlsiMTExMzA4NDMxNTA1NDA3ODkyOTk0NTg5OTA1ODYwMjAwMDA3MTkyODAyNDYxNTM3OTc4ODI4NDMyMTQyOTA1NDE5ODA1MjIzNzUwNzIiLCIxMzAwODQxOTEyOTQzNzgxNzIzMDIyMDMyMzU1ODM2ODkzODMxMTMyOTIwNzgzNzg4NDU1NTMxODM4MjU0NDY1Nzg0NjA1NzYyNzEzIiwiMSJdLCJwaV9iIjpbWyIyMDYxNTc2ODUzNjk4ODQzODMzNjUzNzc3NzkwOTA0MjM1MjA1NjM5Mjg2MjI1MTc4NTcyMjc5NjYzNzU5MDIxMjE2MDU2MTM1MTY1NiIsIjEwMzcxMTQ0ODA2MTA3Nzc4ODkwNTM4ODU3NzAwODU1MTA4NjY3NjIyMDQyMjE1MDk2OTcxNzQ3MjAzMTA1OTk3NDU0NjI1ODE0MDgwIl0sWyIxOTU5ODU0MTM1MDgwNDQ3ODU0OTE0MTIwNzgzNTAyODY3MTExMTA2MzkxNTYzNTU4MDY3OTY5NDkwNzYzNTkxNDI3OTkyODY3NzgxMiIsIjE1MjY0NTUzMDQ1NTE3MDY1NjY5MTcxNTg0OTQzOTY0MzIyMTE3Mzk3NjQ1MTQ3MDA2OTA5MTY3NDI3ODA5ODM3OTI5NDU4MDEyOTEzIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjQ0MzMwOTI3OTgyNTUwODg5MzA4NjI1MTI5MDAwMzkzNjkzNTA3NzM0ODc1NDA5NzQ3MDgxODUyMzU1ODA4MjUwMjM2NDgyMjA0OSIsIjI5ODQxODAyMjc3NjYwNDgxMDA1MTAxMjA0MDcxNTA3NTIwNTIzMzQ1NzE4NzY2ODEzMDQ5OTk1OTU1NDQxMzgxNTU2MTE5NjMyNzMiLCIxIl0sInByb3RvY29sIjoiIn19XX19.5Mu5qwMpE76wJ-Gn6Y8hjME6lo-6XRwUjCBY26EGIYIEJxd2iejgOBlQAqh9OmSsAViAT630vovd6mimw89MOA`
	p := JWSPacker{
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(`{
					"@context": [
						"https://www.w3.org/ns/did/v1",
						"https://w3id.org/security/suites/secp256k1recovery-2020/v2"
					],
					"id": "did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG",
					"verificationMethod": [
					{
						"id": "did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG#vm-1",
						"controller": "did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG",
						"type": "EcdsaSecp256k1RecoveryMethod2020",
						"blockchainAccountId": "eip155:21000:0x964e496a1b2541ed029abd5e49fd01e41cd02995"
					}
					],
					"authentication": ["did:iden3:privado:main:2SZDsdYordSH49VhS6hGo164RLwfcQe9FGow5ftSUG#vm-1"]
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
		didResolverHandler: DIDResolverHandlerFunc(func(_ string) (*verifiable.DIDDocument, error) {
			didDoc := &verifiable.DIDDocument{}
			err := json.Unmarshal([]byte(exampleDidDocJS), didDoc)
			require.NoError(t, err)
			return didDoc, nil
		}),
	}

	_, err := p.Unpack([]byte(token))
	require.ErrorIs(t, err, ErrorVerificationMethodNotFound)
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
			name:           "Vm in auth section (list of vms)",
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
			name:           "Vm in auth section  (list of vms)",
			didDocFileName: "diddocument_with_list_of_did.json",
			kid:            "#vm-2",
			expectedKey: verifiable.CommonVerificationMethod{
				ID:         "#vm-2",
				Controller: "did:test:2",
				Type:       "EcdsaSecp256k1VerificationKey2019",
				PublicKeyJwk: map[string]interface{}{
					"testID": "6",
					"kty":    "EC",
					"crv":    "secp256k1",
					"x":      "WfY7Px6AgH6x-_dgAoRbg8weYRJA36ON-gQiFnETrqw",
					"y":      "IzFx3BUGztK0cyDStiunXbrZYYTtKbOUzx16SUK0sAY",
				},
			},
		},
		{
			name:           "Vm in auth section (full)",
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
			vms, err := resolveVerificationMethods(didDoc)
			require.NoError(t, err)

			vm, err := findVerificationMethodByID(vms, tt.kid)
			require.NoError(t, err)
			require.Equal(t, tt.expectedKey, vm)
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
