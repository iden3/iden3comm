package packers

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
)

func TestJWSPacker_Pack(t *testing.T) {

	p := setupJWSPacker()
	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	_ = "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"

	_, err := p.Pack(msgBytes, SigningParams{SenderDID: `did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29`})
	assert.Nil(t, err)

}

func TestJWSPacker_Unpack(t *testing.T) {

	p := setupJWSPacker()

	msgZKP := []byte(`eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZToxMjMjdm0tMSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiJ9.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDpleGFtcGxlOjEyMyIsImJvZHkiOnsic2NvcGUiOlt7InR5cGUiOiJ6ZXJva25vd2xlZGdlIiwiY2lyY3VpdF9pZCI6ImF1dGgiLCJwdWJfc2lnbmFscyI6WyIxIiwiMTgzMTE1NjA1MjUzODMzMTk3MTkzMTEzOTQ5NTcwNjQ4MjAwOTEzNTQ5NzYzMTA1OTk4MTg3OTcxNTcxODk1Njg2MjE0NjY5NTA4MTEiLCIzMjM0MTY5MjUyNjQ2NjYyMTc2MTcyODg1Njk3NDI1NjQ3MDM2MzI4NTA4MTYwMzU3NjEwODQwMDI3MjAwOTAzNzczNTMyOTc5MjAiXSwicHJvb2ZfZGF0YSI6eyJwaV9hIjpbIjExMTMwODQzMTUwNTQwNzg5Mjk5NDU4OTkwNTg2MDIwMDAwNzE5MjgwMjQ2MTUzNzk3ODgyODQzMjE0MjkwNTQxOTgwNTIyMzc1MDcyIiwiMTMwMDg0MTkxMjk0Mzc4MTcyMzAyMjAzMjM1NTgzNjg5MzgzMTEzMjkyMDc4Mzc4ODQ1NTUzMTgzODI1NDQ2NTc4NDYwNTc2MjcxMyIsIjEiXSwicGlfYiI6W1siMjA2MTU3Njg1MzY5ODg0MzgzMzY1Mzc3Nzc5MDkwNDIzNTIwNTYzOTI4NjIyNTE3ODU3MjI3OTY2Mzc1OTAyMTIxNjA1NjEzNTE2NTYiLCIxMDM3MTE0NDgwNjEwNzc3ODg5MDUzODg1NzcwMDg1NTEwODY2NzYyMjA0MjIxNTA5Njk3MTc0NzIwMzEwNTk5NzQ1NDYyNTgxNDA4MCJdLFsiMTk1OTg1NDEzNTA4MDQ0Nzg1NDkxNDEyMDc4MzUwMjg2NzExMTEwNjM5MTU2MzU1ODA2Nzk2OTQ5MDc2MzU5MTQyNzk5Mjg2Nzc4MTIiLCIxNTI2NDU1MzA0NTUxNzA2NTY2OTE3MTU4NDk0Mzk2NDMyMjExNzM5NzY0NTE0NzAwNjkwOTE2NzQyNzgwOTgzNzkyOTQ1ODAxMjkxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTY0NDMzMDkyNzk4MjU1MDg4OTMwODYyNTEyOTAwMDM5MzY5MzUwNzczNDg3NTQwOTc0NzA4MTg1MjM1NTgwODI1MDIzNjQ4MjIwNDkiLCIyOTg0MTgwMjI3NzY2MDQ4MTAwNTEwMTIwNDA3MTUwNzUyMDUyMzM0NTcxODc2NjgxMzA0OTk5NTk1NTQ0MTM4MTU1NjExOTYzMjczIiwiMSJdLCJwcm90b2NvbCI6IiJ9fV19fQ.de_qaDM7VYFaPUCNDGsvwF04tT4S4nXBO8dqXnU8XAof0Uip5LDCe4-IjEBPxu0sLh8BxcvPHMYMjx_pvPcqWw`)
	iden3msg, err := p.Unpack(msgZKP)
	assert.NoError(t, err)
	msgBytes, err := json.Marshal(iden3msg)
	assert.Nil(t, err)
	var authResponse protocol.AuthorizationResponseMessage
	err = json.Unmarshal(msgBytes, &authResponse)
	assert.Nil(t, err)
	fmt.Println(string(msgBytes))
	assert.Equal(t, protocol.AuthorizationResponseMessageType, authResponse.Type)
	assert.Len(t, authResponse.Body.Scope, 1)

}

func setupJWSPacker() *JWSPacker {
	return NewJWSPacker(func(did string) (verifiable.DIDDocument, error) {
		var doc verifiable.DIDDocument
		_ = json.Unmarshal([]byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2",{"esrs2020":"https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","privateKeyJwk":{"@id":"esrs2020:privateKeyJwk","@type":"@json"},"publicKeyHex":"esrs2020:publicKeyHex","privateKeyHex":"esrs2020:privateKeyHex","ethereumAddress":"esrs2020:ethereumAddress"}],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#vm-1","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw","kty":"EC","x":"_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk","y":"Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc"}}],"authentication":["did:example:123#vm-1"]}`), &doc)
		return doc, nil
	}, func(keyID string) (key interface{}, err error) {
		bb, _ := hex.DecodeString(`278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f`)
		k := ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{},
			D:         new(big.Int).SetBytes(bb),
		}
		return k, nil
	})
}
