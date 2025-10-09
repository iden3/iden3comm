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

func TestEncryptedCredentialIssuanceMessage(t *testing.T) {
	data := `{
          "ciphertext": "G94AlOo9R0Bz1L8ypk_Ls4KyjbxjsU2FK3X-HZifdkC9mcVP3wZ4zc2Lgca4jlLzHG4bG5LSS9spVhiZhZ0FFq6Lyo8PtEVAxvW8QmquvgHJ5kJqYK1Wuiry-_hzIdwJqBwc3SCIkTi15KON-LaBFW20dRS4QN8BFVQw6inbxb7gA3ULqLxU-iy6A2oHRiHTQ5A-8PrPvURtf6kxaP1JZ6ozmMSLfpZY7WezvFCgnokYa4eeIoDYYBduSxMnGdYbSZqq_wN-WujTxc1hVdyOYiz-YaZs6UiemzGl8_5F5i5B4Mx0Pf28kzTUzs3ivZtawtWPI8mxNdIuPRg4ivrz2EooIBba9eAEgMj_JdYFI9RQtf0LlCBlcIzdnsC_BwSZgpM5alqOUgRH7SECMB00oon73qlw0ZxLbqxSScXcStwHaJEcrrKw5ZzsM5IB7etqP4Wz9q95e8V3y79ms7l4m48HqbcXjQ",
          "encrypted_key": "aF0cMjVh4k2je1Y5neP-JD_Z4gSXkbfcVwq-S4f_4-5vCqY7kJAtQZYeyaLSVweU2inm5hvwYgf9dnn7q4wX_P1tPLAS5jYYSJd5-ev89av2vlGIPQApAshcKGrTM01Zg9Ewl19bCoTXsfU632AC4V3_Qj5-nkl3m7M-_7rVbvj8yeLtJaYDHdDnF7OORZrYnu-vYENArnhHuE4S9MsnByF2TSO_eZ0_aL8DljTvtvjo9G6J8tV5IbuRz6nOokVuRHoPlyq22ONACW7nHh1sGVd7gTeztsT2z9JAi5szdMe23rgbpTu3FbnG7yxAunQ5MnCLJ5OljGK1BDLpdPOrpw",
          "iv": "ZrFLdKgYqa1LrWIC",
          "protected": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGlkOmlkZW4zOmJpbGxpb25zOnRlc3Q6MlZ4bm9pTnFkTVB5SE10VXdBRXpobldxWEdrRWVKcEFwNG50VGtMOFhUI2tleTEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tZW5jcnlwdGVkLWpzb24ifQ",
          "tag": "rbUb5eW4Hgng-AMd-OPxeQ"
    }`
	proof := `[
          {
            "type": "BJJSignature2021",
            "issuerData": {
              "id": "did:iden3:polygon:amoy:xHV7UUYn7tx3KyzcyXTcnLjvAA9tJRVWCVGErQFRV",
              "state": {
                "claimsTreeRoot": "dd80f4cbef4290fdb5aa73ae95d9c65ea421b766a9d335ad1204255386851d1c",
                "value": "1d633c6d18e8101341f67da2d2e4448244d5e75f230080d8ae802781e8220d19"
              },
              "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f4223360d1687fa64ab33ee8ce4ed1c03cba411d6205e418b844be5cbe7be5041468649e0d60e2294f9f5e866b8670d198c0f3110b2f093317ba368e6264b91d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "mtp": {
                "existence": true,
                "siblings": []
              },
              "credentialStatus": {
                "id": "https://simple.rhs.node/node?state=1d633c6d18e8101341f67da2d2e4448244d5e75f230080d8ae802781e8220d19",
                "revocationNonce": 0,
                "statusIssuer": {
                  "id": "https://simple.issuer.node/v2/agent",
                  "revocationNonce": 0,
                  "type": "Iden3commRevocationStatusV1.0"
                },
                "type": "Iden3ReverseSparseMerkleTreeProof"
              }
            },
            "coreClaim": "7ed2bce3d6fab6efe706a7e76a0881dd2200000000000000000000000000000001b15b112b1036337c49e97a8f9abd452878bebed4a2c2fac91def928b550e00078e912f71bf9d3979a21d140bea8f2d5f620a8cacbf7e5e3b3d0f48ed6beb2d0000000000000000000000000000000000000000000000000000000000000000326d785600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "25c7962a5a11d906d490cc6cf522d332405326ec82f35ee5538301557a314628b452b4fca9292613cb2f9983c5ea6b0ea5411b793d3796b232abe84875c94001"
          }
        ]`

	var p verifiable.CredentialProofs
	require.NoError(t, json.Unmarshal([]byte(proof), &p))

	encryptedCredential := protocol.EncryptedCredentialIssuanceMessage{
		ID:       uuid.NewString(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.EncryptedCredentialIssuanceResponseMessageType,
		ThreadID: uuid.NewString(),
		Body: protocol.EncryptedIssuanceMessageBody{
			ID:      "urn:uuid:ef65ac39-8941-11f0-8c71-0a58a9feac02",
			Data:    json.RawMessage(data),
			Type:    "KYCAgeCredential",
			Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
			Proof:   p,
		},
		From: "did:iden3:polygon:amoy:xHV7UUYn7tx3KyzcyXTcnLjvAA9tJRVWCVGErQFRV",
		To:   "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE",
	}

	marshalled, err := json.Marshal(encryptedCredential)
	require.NoError(t, err)

	var message protocol.EncryptedCredentialIssuanceMessage
	err = json.Unmarshal(marshalled, &message)
	require.NoError(t, err)

	require.Equal(t, encryptedCredential.ID, message.ID)
	require.Equal(t, encryptedCredential.Typ, message.Typ)
	require.Equal(t, encryptedCredential.Type, message.Type)
	require.Equal(t, encryptedCredential.ThreadID, message.ThreadID)
	require.Equal(t, encryptedCredential.From, message.From)
	require.Equal(t, encryptedCredential.To, message.To)
	require.Equal(t, encryptedCredential.Body.ID, message.Body.ID)
	require.Equal(t, encryptedCredential.Body.Type, message.Body.Type)
	require.Equal(t, encryptedCredential.Body.Context, message.Body.Context)
	require.Equal(t, encryptedCredential.Body.Proof, message.Body.Proof)
}
