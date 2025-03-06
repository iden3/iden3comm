package protocol

import (
	"encoding/json"

	"github.com/iden3/iden3comm/v2"
)

const (
	// ContractInvokeRequestMessageType defines contract invoke request type of the communication protocol
	ContractInvokeRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "proofs/1.0/contract-invoke-request"
	// ContractInvokeResponseMessageType defines contract invoke response type of the communication protocol
	ContractInvokeResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "proofs/1.0/contract-invoke-response"
)

// ContractInvokeRequestMessage is struct the represents iden3message contract invoke request
type ContractInvokeRequestMessage struct {
	Body ContractInvokeRequestMessageBody `json:"body,omitempty"`
	iden3comm.BasicMessage
}

// ContractInvokeRequestMessageBody is body for contract invoke request
type ContractInvokeRequestMessageBody struct {
	Reason          string                      `json:"reason,omitempty"`
	TransactionData TransactionData             `json:"transaction_data"`
	DIDDoc          json.RawMessage             `json:"did_doc,omitempty"`
	Scope           []ZeroKnowledgeProofRequest `json:"scope"`
}

// TransactionData represents structure for on chain verification
type TransactionData struct {
	ContractAddress string `json:"contract_address"`
	MethodID        string `json:"method_id"`
	ChainID         int    `json:"chain_id"`
	Network         string `json:"network"`
}

// ContractInvokeResponseMessage is struct the represents iden3message contract invoke response
type ContractInvokeResponseMessage struct {
	Body ContractInvokeResponseMessageBody `json:"body,omitempty"`
	iden3comm.BasicMessage
}

// ContractInvokeResponseMessageBody is body for contract invoke response
type ContractInvokeResponseMessageBody struct {
	TransactionData TransactionData                     `json:"transaction_data"`
	DIDDoc          json.RawMessage                     `json:"did_doc,omitempty"`
	Scope           []OnchainZeroKnowledgeProofResponse `json:"scope"`
}

// OnchainZeroKnowledgeProofResponse represents structure of zkp response given for onchain verification
type OnchainZeroKnowledgeProofResponse struct {
	ZeroKnowledgeProofResponse
	TxHash string `json:"txHash"`
}
