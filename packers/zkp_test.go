package packers

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-jwz/v2"
	"github.com/iden3/iden3comm/v2/mock"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
)

func TestZKPPacker_Pack(t *testing.T) {

	mockedProvingMethod := &mock.ProvingMethodGroth16AuthV2{
		ProvingMethodAlg: jwz.ProvingMethodAlg{
			Alg:       "groth16-mock",
			CircuitID: "authV2",
		},
	}

	jwz.RegisterProvingMethod(mockedProvingMethod.ProvingMethodAlg, func() jwz.ProvingMethod {
		return mockedProvingMethod
	})

	mockVerificationParam := make(map[jwz.ProvingMethodAlg]VerificationParams)
	mockVerificationParam[mockedProvingMethod.ProvingMethodAlg] = NewVerificationParams([]byte(""), verifyStateMock)

	mockProvingParamMap := make(map[jwz.ProvingMethodAlg]ProvingParams)
	mockProvingParamMap[mockedProvingMethod.ProvingMethodAlg] =
		NewProvingParams(mock.PrepareAuthInputs, []byte{}, []byte{})

	p := NewZKPPacker(mockProvingParamMap, mockVerificationParam)

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:polygonid:polygon:mumbai:2qK8oh6weN7H3Z8ji5YwV8Y9BF7qJfJnZ7XCdSCWo7","to":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","typ":"application/iden3-zkp-json","body":{"scope":[]}}`)

	identifier := "did:polygonid:polygon:mumbai:2qK8oh6weN7H3Z8ji5YwV8Y9BF7qJfJnZ7XCdSCWo7"

	senderDID, err := w3c.ParseDID(identifier)
	assert.NoError(t, err)

	b, err := p.Pack(msgBytes, ZKPPackerParams{
		SenderID:         senderDID,
		ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "authV2"},
	})
	assert.Nil(t, err)

	token, err := jwz.Parse(string(b))
	assert.Nil(t, err)

	fmt.Println(string(b))
	outs := circuits.AuthV2PubSignals{}
	err = token.ParsePubSignals(&outs)
	assert.Nil(t, err)

	didFromToken, err := core.ParseDIDFromID(*outs.UserID)
	assert.Nil(t, err)

	assert.EqualValues(t, senderDID.String(), didFromToken.String())

}

func TestPlainMessagePacker_Unpack(t *testing.T) {
	mockedProvingMethod := &mock.ProvingMethodGroth16AuthV2{
		ProvingMethodAlg: jwz.ProvingMethodAlg{
			Alg:       "groth16-mock",
			CircuitID: "authV2",
		},
	}

	jwz.RegisterProvingMethod(mockedProvingMethod.ProvingMethodAlg, func() jwz.ProvingMethod {
		return mockedProvingMethod
	})

	mockVerificationParam := make(map[jwz.ProvingMethodAlg]VerificationParams)
	mockVerificationParam[mockedProvingMethod.ProvingMethodAlg] = NewVerificationParams([]byte(""), verifyStateMock)

	mockProvingParamMap := make(map[jwz.ProvingMethodAlg]ProvingParams)
	mockProvingParamMap[mockedProvingMethod.ProvingMethodAlg] =
		NewProvingParams(mock.PrepareAuthInputs, []byte{}, []byte{})

	jwz.RegisterProvingMethod(mockedProvingMethod.ProvingMethodAlg, func() jwz.ProvingMethod {
		return mockedProvingMethod
	})
	p := NewZKPPacker(mockProvingParamMap, mockVerificationParam)

	msgZKP := []byte(`eyJhbGciOiJncm90aDE2LW1vY2siLCJjaXJjdWl0SWQiOiJhdXRoVjIiLCJjcml0IjpbImNpcmN1aXRJZCJdLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuMy16a3AtanNvbiJ9.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFLOG9oNndlTjdIM1o4amk1WXdWOFk5QkY3cUpmSm5aN1hDZFNDV283IiwidG8iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6eDRqY0hQNFhIVEszdlg1OEFIWlB5SEU4a1lqbmV5RTZGWlJmejdLMjkiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuMy16a3AtanNvbiIsImJvZHkiOnsic2NvcGUiOltdfX0.eyJwcm9vZiI6eyJwaV9hIjpudWxsLCJwaV9iIjpudWxsLCJwaV9jIjpudWxsLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMjYyNDA1Mzc4ODEyODUzMDM4NjY5NTk5MTQ4NzM1MDEyMTU5MDQxMDAyNDY1NDE1Njg2Mjk5NjMzMTAzMDk1MDY4MTczMzE3MTQiLCIxNjc1MzkyOTI5MDYxNzcyMzAzNTIzNjI5NzIwNzk4MDAyNDUwMDA4NjM1NjI0NzU5NzE5NjI0MTEwMTg2NDAyMzI4NzI2NjUwNjA4OCIsIjY5MzU3OTU1NTQ1MDgxMjEwNzQ5MzkyMDQ2NTUyNjU3ODIyNDQzOTkzNDc1Nzc3MzY5OTE0MTAzMjMzOTE5NDg5MzYzOTgyNTkwOTMiXX0`)
	iden3msg, err := p.Unpack(msgZKP)
	assert.NoError(t, err)
	msgBytes, err := json.Marshal(iden3msg)
	assert.Nil(t, err)
	var authResponse protocol.AuthorizationResponseMessage
	err = json.Unmarshal(msgBytes, &authResponse)
	assert.Nil(t, err)

	assert.Equal(t, protocol.AuthorizationResponseMessageType, authResponse.Type)
	assert.Len(t, authResponse.Body.Scope, 0)

}

func verifyStateMock(_ circuits.CircuitID, _ []string, _ ...DefaultZKPUnpackerOption) error {
	return nil
}
