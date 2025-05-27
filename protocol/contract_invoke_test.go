package protocol_test

import (
	"encoding/json"
	"testing"

	uuid "github.com/google/uuid"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)

func TestContractInvokeResponseMessageCreation(t *testing.T) {
	var err error

	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	didStr := "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	require.NoError(t, err)

	invokeResponse := protocol.ContractInvokeResponseMessage{
		ID:       id.String(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.ContractInvokeResponseMessageType,
		ThreadID: thID.String(),
		Body: protocol.ContractInvokeResponseMessageBody{
			TransactionData: protocol.TransactionData{
				ContractAddress: "0x1234",
				MethodID:        "0x132456",
				ChainID:         1,
				Network:         "polygon-amoy",
			},
			Scope: []protocol.OnchainZeroKnowledgeProofResponse{
				{
					ZeroKnowledgeProofResponse: protocol.ZeroKnowledgeProofResponse{
						ID:        1,
						CircuitID: "234234",
						ZKProof: types.ZKProof{
							Proof: &types.ProofData{
								A:        []string{"1", "2"},
								B:        [][]string{{"1", "2"}, {"3,4"}},
								C:        []string{"4", "2"},
								Protocol: "groth16",
							},
							PubSignals: []string{"1", "23"},
						},
					},
					TxHash: "0x2345",
				},
			},
		},
		From: didStr,
		To:   "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL",
	}

	marshalledReq, err := json.Marshal(invokeResponse)
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"f0885dd0-e60e-11ee-b3e8-de17148ce1ce","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/proofs/1.0/contract-invoke-response","thid":"f08860d2-e60e-11ee-b3e8-de17148ce1ce","body":{"transaction_data":{"contract_address":"0x1234","method_id":"0x132456","chain_id":1,"network":"polygon-amoy"},"scope":[{"id":1,"circuitId":"234234","proof":{"pi_a":["1","2"],"pi_b":[["1","2"],["3,4"]],"pi_c":["4","2"],"protocol":"groth16"},"pub_signals":["1","23"],"txHash":"0x2345"}]},"from":"did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE","to":"did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"}`, string(marshalledReq))

	var unmarshalledReq protocol.ContractInvokeResponseMessage
	err = json.Unmarshal(marshalledReq, &unmarshalledReq)

	require.Len(t, unmarshalledReq.Body.Scope, 1)
	require.Equal(t, unmarshalledReq.Body.Scope[0].ID, invokeResponse.Body.Scope[0].ID)
}
