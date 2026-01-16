package protocol_test

import (
	"encoding/json"
	"math/big"
	"testing"
	"fmt"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"

	uuid "github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)


func TestCreationDIDCommCompatibleMessage(t *testing.T) {

	var err error
	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	mobileService := verifiable.Service{
		ID:              fmt.Sprintf("%s#%s", didStr, "wallet"),
		Type:            verifiable.Iden3MobileServiceType,
		ServiceEndpoint: "iden3:v0.1:callbackHandler",
	}
	didDoc := &verifiable.DIDDocument{
		ID:      didStr,
		Context: "https://www.w3.org/ns/did/v1",
		Service: []interface{}{mobileService},
	}
	didDocBytes, err := json.Marshal(didDoc)
	require.NoError(t, err)
	authRequest := protocol.AuthorizationRequestMessage{
		BasicMessage: iden3comm.BasicMessage{
			ID:       id.String(),
			Typ:      packers.MediaTypePlainMessage,
			Type:     protocol.AuthorizationRequestMessageType,
			ThreadID: thID.String(),
			From:     didStr,
			To:       "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
		},
		Body: protocol.AuthorizationRequestMessageBody{
			Scope: []protocol.ZeroKnowledgeProofRequest{{
				ID:        1,
				CircuitID: "testCircuiID",
				Query: map[string]interface{}{
					"type":    "KYCAgeCredential",
					"context": "http://context.example.com",
				},
			}},
			CallbackURL: "http://test.com",
			DIDDoc:      didDocBytes,
		},
	}

	marshalledReq, err := json.Marshal(authRequest)
	require.NoError(t, err)
	t.Log(string(marshalledReq))

	var a protocol.AuthorizationRequestMessage
	err = json.Unmarshal(marshalledReq, &a)
	require.NoError(t, err)

	marshalledReq2, err := json.Marshal(a)
	require.NoError(t, err)
	t.Log(string(marshalledReq2))

	require.JSONEq(t, string(marshalledReq), string(marshalledReq2))
}

func TestCreationDIDCommCompatibleMessage2(t *testing.T) {

	var err error
	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	mobileService := verifiable.Service{
		ID:              fmt.Sprintf("%s#%s", didStr, "wallet"),
		Type:            verifiable.Iden3MobileServiceType,
		ServiceEndpoint: "iden3:v0.1:callbackHandler",
	}
	didDoc := &verifiable.DIDDocument{
		ID:      didStr,
		Context: "https://www.w3.org/ns/did/v1",
		Service: []interface{}{mobileService},
	}
	didDocBytes, err := json.Marshal(didDoc)
	require.NoError(t, err)
	authRequest := protocol.AuthorizationRequestMessage{
		BasicMessage: iden3comm.BasicMessage{
			ID:        id.String(),
			Typ:       packers.MediaTypePlainMessage,
			Type:      protocol.AuthorizationRequestMessageType,
			ThreadID:  thID.String(),
			From:      didStr,
			DIDCommTo: []string{"did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"},
		},
		Body: protocol.AuthorizationRequestMessageBody{
			Scope: []protocol.ZeroKnowledgeProofRequest{{
				ID:        1,
				CircuitID: "testCircuiID",
				Query: map[string]interface{}{
					"type":    "KYCAgeCredential",
					"context": "http://context.example.com",
				},
			}},
			CallbackURL: "http://test.com",
			DIDDoc:      didDocBytes,
		},
	}

	marshalledReq, err := json.Marshal(authRequest)
	require.NoError(t, err)
	t.Log(string(marshalledReq))
	var a protocol.AuthorizationRequestMessage
	err = json.Unmarshal(marshalledReq, &a)
	require.NoError(t, err)

	marshalledReq2, err := json.Marshal(a)
	require.NoError(t, err)
	t.Log(string(marshalledReq2))

	require.JSONEq(t, string(marshalledReq), string(marshalledReq2))
}

func TestAuthRequestCreationRegular(t *testing.T) {
	var err error

	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	authorizationRequestMessage := protocol.AuthorizationRequestMessage{
		BasicMessage: iden3comm.BasicMessage{
			ID:       id.String(),
			Typ:      packers.MediaTypePlainMessage,
			Type:     protocol.AuthorizationRequestMessageType,
			ThreadID: thID.String(),
			From: didStr,
			To:   "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",

		},
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: "https://callback.url",
			Message:     "some msg",
			Reason:      "some reason",
			Scope: []protocol.ZeroKnowledgeProofRequest{
				{
					ID:        1,
					CircuitID: "c-1",
					Query: map[string]interface{}{
						"type": "test",
					},
				},
			},
		},
	}

	marshalledReq, err := json.Marshal(authorizationRequestMessage)
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"f0885dd0-e60e-11ee-b3e8-de17148ce1ce","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/authorization/1.0/request","thid":"f08860d2-e60e-11ee-b3e8-de17148ce1ce","body":{"callbackUrl":"https://callback.url","reason":"some reason","message":"some msg","scope":[{"id":1,"circuitId":"c-1","query":{"type":"test"}}]},"from":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE","to":"did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"}`, string(marshalledReq))

	var reqAfterUnmarshall protocol.AuthorizationRequestMessage
	err = json.Unmarshal(marshalledReq, &reqAfterUnmarshall)
	require.NoError(t, err)

	require.Len(t, authorizationRequestMessage.Body.Scope, 1)
	require.Equal(t, authorizationRequestMessage.Body.Scope[0].ID, reqAfterUnmarshall.Body.Scope[0].ID)
}

func TestAuthRequestCreationExtendedID(t *testing.T) {
	var err error

	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	authorizationRequestMessage := protocol.AuthorizationRequestMessage{
		BasicMessage: iden3comm.BasicMessage{
			ID:       id.String(),
			Typ:      packers.MediaTypePlainMessage,
			Type:     protocol.AuthorizationRequestMessageType,
			ThreadID: thID.String(),
			From: didStr,
			To:   "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
		},
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: "https://callback.url",
			Message:     "some msg",
			Reason:      "some reason",
			Scope: []protocol.ZeroKnowledgeProofRequest{
				{
					ExtendedID: big.NewInt(134324234),
					CircuitID:  "c-1",
					Query: map[string]interface{}{
						"type": "test",
					},
				},
			},
		},
	}

	marshalledReq, err := json.Marshal(authorizationRequestMessage)
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"f0885dd0-e60e-11ee-b3e8-de17148ce1ce","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/authorization/1.0/request","thid":"f08860d2-e60e-11ee-b3e8-de17148ce1ce","body":{"callbackUrl":"https://callback.url","reason":"some reason","message":"some msg","scope":[{"id":"134324234","circuitId":"c-1","query":{"type":"test"}}]},"from":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE","to":"did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"}`, string(marshalledReq))

	var reqAfterUnmarshall protocol.AuthorizationRequestMessage
	err = json.Unmarshal(marshalledReq, &reqAfterUnmarshall)
	require.NoError(t, err)

	require.Len(t, authorizationRequestMessage.Body.Scope, 1)
	require.Equal(t, authorizationRequestMessage.Body.Scope[0].ExtendedID, reqAfterUnmarshall.Body.Scope[0].ExtendedID)
}

func TestAuthRequestCreationBothIDAreSetShouldFail(t *testing.T) {
	var err error

	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	authRequestMessage := protocol.AuthorizationRequestMessage{
		BasicMessage: iden3comm.BasicMessage{
			ID:       id.String(),
			Typ:      packers.MediaTypePlainMessage,
			Type:     protocol.AuthorizationRequestMessageType,
			ThreadID: thID.String(),
			From: didStr,
			To:   "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
		},
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: "https://callback.url",
			Message:     "some msg",
			Reason:      "some reason",
			Scope: []protocol.ZeroKnowledgeProofRequest{
				{
					ID:         1,
					ExtendedID: big.NewInt(134324234),
					CircuitID:  "c-1",
					Query: map[string]interface{}{
						"type": "test",
					},
				},
			},
		},
	}

	_, err = json.Marshal(authRequestMessage)
	require.ErrorContains(t, err, "only one field for ZeroKnowledgeProofRequest must be initiated, ExtendedID or ID")

}
