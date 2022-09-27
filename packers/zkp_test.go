package packers

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-jwz"
	"github.com/iden3/iden3comm/mock"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestZKPPacker_Pack(t *testing.T) {

	// mocked keys
	keys := map[circuits.CircuitID][]byte{circuits.AuthCircuitID: {}}
	provingKey := []byte{}
	wasm := []byte{}

	mockedProvingMethod := &mock.ProvingMethodGroth16Auth{Algorithm: "groth16-mock", Circuit: "auth"}

	jwz.RegisterProvingMethod("groth16-mock", func() jwz.ProvingMethod {
		return mockedProvingMethod
	})

	p := NewZKPPacker(mockedProvingMethod, mock.PrepareAuthInputs, mock.VerifyState, provingKey, wasm, keys)

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:4RzqiKYtZjWu8xf1jnts3FTpPnwTzW1HyUsdDGcDER6","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)
	identifier := "did:iden3:polygon:mumbai:4RzqiKYtZjWu8xf1jnts3FTpPnwTzW1HyUsdDGcDER6"

	senderDID, err := core.ParseDID(identifier)
	assert.Nil(t, err)

	b, err := p.Pack(msgBytes, ZKPPackerParams{
		SenderID: senderDID,
	})
	assert.Nil(t, err)

	token, err := jwz.Parse(string(b))
	assert.Nil(t, err)
	fmt.Println(string(b))
	outs := circuits.AuthPubSignals{}
	err = token.ParsePubSignals(&outs)
	assert.Nil(t, err)

	didFromToken, err := core.ParseDIDFromID(*outs.UserID)
	assert.Nil(t, err)

	assert.EqualValues(t, senderDID.String(), didFromToken.String())

}

func TestZKPPacker_Unpack(t *testing.T) {
	keys := map[circuits.CircuitID][]byte{circuits.AuthCircuitID: {}}
	provingKey := []byte{}
	wasm := []byte{}

	mockedProvingMethod := &mock.ProvingMethodGroth16Auth{Algorithm: "groth16-mock", Circuit: "auth"}

	jwz.RegisterProvingMethod("groth16-mock", func() jwz.ProvingMethod {
		return mockedProvingMethod
	})
	p := NewZKPPacker(mockedProvingMethod, mock.PrepareAuthInputs, mock.VerifyState, provingKey, wasm, keys)

	msgZKP := []byte(`eyJhbGciOiJncm90aDE2LW1vY2siLCJjaXJjdWl0SWQiOiJhdXRoIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTo0UnpxaUtZdFpqV3U4eGYxam50czNGVHBQbndUelcxSHlVc2RER2NERVI2IiwiYm9keSI6eyJzY29wZSI6W3sidHlwZSI6Inplcm9rbm93bGVkZ2UiLCJjaXJjdWl0X2lkIjoiYXV0aCIsInB1Yl9zaWduYWxzIjpbIjEiLCIxODMxMTU2MDUyNTM4MzMxOTcxOTMxMTM5NDk1NzA2NDgyMDA5MTM1NDk3NjMxMDU5OTgxODc5NzE1NzE4OTU2ODYyMTQ2Njk1MDgxMSIsIjMyMzQxNjkyNTI2NDY2NjIxNzYxNzI4ODU2OTc0MjU2NDcwMzYzMjg1MDgxNjAzNTc2MTA4NDAwMjcyMDA5MDM3NzM1MzI5NzkyMCJdLCJwcm9vZl9kYXRhIjp7InBpX2EiOlsiMTExMzA4NDMxNTA1NDA3ODkyOTk0NTg5OTA1ODYwMjAwMDA3MTkyODAyNDYxNTM3OTc4ODI4NDMyMTQyOTA1NDE5ODA1MjIzNzUwNzIiLCIxMzAwODQxOTEyOTQzNzgxNzIzMDIyMDMyMzU1ODM2ODkzODMxMTMyOTIwNzgzNzg4NDU1NTMxODM4MjU0NDY1Nzg0NjA1NzYyNzEzIiwiMSJdLCJwaV9iIjpbWyIyMDYxNTc2ODUzNjk4ODQzODMzNjUzNzc3NzkwOTA0MjM1MjA1NjM5Mjg2MjI1MTc4NTcyMjc5NjYzNzU5MDIxMjE2MDU2MTM1MTY1NiIsIjEwMzcxMTQ0ODA2MTA3Nzc4ODkwNTM4ODU3NzAwODU1MTA4NjY3NjIyMDQyMjE1MDk2OTcxNzQ3MjAzMTA1OTk3NDU0NjI1ODE0MDgwIl0sWyIxOTU5ODU0MTM1MDgwNDQ3ODU0OTE0MTIwNzgzNTAyODY3MTExMTA2MzkxNTYzNTU4MDY3OTY5NDkwNzYzNTkxNDI3OTkyODY3NzgxMiIsIjE1MjY0NTUzMDQ1NTE3MDY1NjY5MTcxNTg0OTQzOTY0MzIyMTE3Mzk3NjQ1MTQ3MDA2OTA5MTY3NDI3ODA5ODM3OTI5NDU4MDEyOTEzIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjQ0MzMwOTI3OTgyNTUwODg5MzA4NjI1MTI5MDAwMzkzNjkzNTA3NzM0ODc1NDA5NzQ3MDgxODUyMzU1ODA4MjUwMjM2NDgyMjA0OSIsIjI5ODQxODAyMjc3NjYwNDgxMDA1MTAxMjA0MDcxNTA3NTIwNTIzMzQ1NzE4NzY2ODEzMDQ5OTk1OTU1NDQxMzgxNTU2MTE5NjMyNzMiLCIxIl0sInByb3RvY29sIjoiIn19XX19.eyJwcm9vZiI6eyJwaV9hIjpudWxsLCJwaV9iIjpudWxsLCJwaV9jIjpudWxsLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMSIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzI2OTUwNjM5OTMzMjA5OTg0MDk2ODc4MTIwNjQ0NzM2NjE3MDQ2Mjc1NzIzMjA5MzUzMzg2OTA3NjQ1MTE3Nzg0NTgwNjIwNzY5Il19`)
	iden3msg, err := p.Unpack(msgZKP)
	assert.Nil(t, err)
	msgBytes, err := json.Marshal(iden3msg)
	assert.Nil(t, err)
	var authResponse protocol.AuthorizationResponseMessage
	err = json.Unmarshal(msgBytes, &authResponse)
	assert.Nil(t, err)

	assert.Equal(t, authResponse.Type, protocol.AuthorizationResponseMessageType)
	assert.Len(t, authResponse.Body.Scope, 1)

}
