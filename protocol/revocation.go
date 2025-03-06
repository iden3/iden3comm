package protocol

import (
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
)

const (
	// RevocationStatusRequestMessageType is type for request of revocation status
	RevocationStatusRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/request-status"
	// RevocationStatusResponseMessageType is type for response with a revocation status
	RevocationStatusResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/status"
)

// RevocationStatusRequestMessage is struct the represents body for proof generation request
type RevocationStatusRequestMessage struct {
	iden3comm.BasicMessage
	Body RevocationStatusRequestMessageBody `json:"body,omitempty"`
}

// RevocationStatusRequestMessageBody is struct the represents request for revocation status
type RevocationStatusRequestMessageBody struct {
	RevocationNonce uint64 `json:"revocation_nonce"`
}

// RevocationStatusResponseMessage is struct the represents body for proof generation request
type RevocationStatusResponseMessage struct {
	iden3comm.BasicMessage
	Body RevocationStatusResponseMessageBody `json:"body,omitempty"`
}

// RevocationStatusResponseMessageBody is struct the represents request for revocation status
type RevocationStatusResponseMessageBody struct {
	verifiable.RevocationStatus
}
