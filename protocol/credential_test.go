package protocol_test

import (
	"encoding/json"
	"fmt"
	"testing"

	uuid "github.com/google/uuid"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)

func TestCredentialProposalRequestMessageCreation(t *testing.T) {

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
	proposalRequest := protocol.CredentialsProposalRequestMessage{
		ID:       id.String(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.CredentialProposalRequestMessageType,
		ThreadID: thID.String(),
		Body: protocol.CredentialsProposalRequestBody{
			Credentials: []protocol.CredentialInfo{
				{
					Type:    "KYCAgeCredential",
					Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				},
			},
			DIDDoc: didDocBytes,
		},
		From: didStr,
		To:   "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
	}

	marshalledReq, err := json.Marshal(proposalRequest)
	require.NoError(t, err)

	require.JSONEq(t, `{"id":"f0885dd0-e60e-11ee-b3e8-de17148ce1ce","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/credentials/0.1/proposal-request","thid":"f08860d2-e60e-11ee-b3e8-de17148ce1ce","body":{"credentials":[{"type":"KYCAgeCredential","context":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"}],"did_doc":{"@context":"https://www.w3.org/ns/did/v1","id":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE","service":[{"id":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE#wallet","type":"Iden3MobileServiceV1","serviceEndpoint":"iden3:v0.1:callbackHandler"}]}},"from":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE","to":"did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"}`, string(marshalledReq))
}
func TestCredentialProposalMessageCreation(t *testing.T) {

	var err error
	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	proposalRequest := protocol.CredentialsProposalMessage{
		ID:       id.String(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.CredentialProposalMessageType,
		ThreadID: thID.String(),
		Body: protocol.CredentialsProposalBody{
			Proposals: []protocol.CredentialProposalInfo{
				{
					Credentials: []protocol.CredentialInfo{
						{
							Type:    "KYCAgeCredential",
							Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						}},
					Type:        protocol.CredentialProposalTypeWeb,
					URL:         "http://test.com?sessionId=1",
					Description: "web page with some flow",
				},
			},
		},
		From: "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
		To:   didStr,
	}

	marshalledReq, err := json.Marshal(proposalRequest)
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"f0885dd0-e60e-11ee-b3e8-de17148ce1ce","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/credentials/0.1/proposal","thid":"f08860d2-e60e-11ee-b3e8-de17148ce1ce","body":{"proposals":[{"credentials":[{"type":"KYCAgeCredential","context":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"}],"type":"WebVerificationFormV1.0","url":"http://test.com?sessionId=1","description":"web page with some flow"}]},"from":"did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL","to":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"}`, string(marshalledReq))
}

func TestCredentialOfferMessageCreation(t *testing.T) {

	var err error
	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	require.NoError(t, err)
	proposalRequest := protocol.CredentialsOfferMessage{
		ID:       id.String(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.CredentialOfferMessageType,
		ThreadID: thID.String(),
		Body: protocol.CredentialsOfferMessageBody{
			URL: "http://test.com",
			Credentials: []protocol.CredentialOffer{
				{
					ID:          id.String(),
					Description: "test 1",
					Status:      protocol.CredentialOfferStatusPending,
				},
				{
					ID:          thID.String(),
					Description: "test 2",
					// no status is completed
				},
			},
		},
		From: didStr,
		To:   "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
	}

	marshalledReq, err := json.Marshal(proposalRequest)
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"f0885dd0-e60e-11ee-b3e8-de17148ce1ce","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/credentials/1.0/offer","thid":"f08860d2-e60e-11ee-b3e8-de17148ce1ce","body":{"url":"http://test.com","credentials":[{"id":"f0885dd0-e60e-11ee-b3e8-de17148ce1ce","description":"test 1","status":"pending"},{"id":"f08860d2-e60e-11ee-b3e8-de17148ce1ce","description":"test 2"}]},"from":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE","to":"did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"}`, string(marshalledReq))
}
