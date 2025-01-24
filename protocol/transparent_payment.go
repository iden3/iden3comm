package protocol

import (
	"github.com/iden3/iden3comm/v2"
)

const (
	// TransparentPaymentInstructionMessageType defines the message type for transparent payment instruction
	TransparentPaymentInstructionMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/transparent-payment-instruction"
)

// TransparentPaymentInstructionMessage represents a message for transparent payment instruction
type TransparentPaymentInstructionMessage struct {
	ID       string                                   `json:"id"`
	Typ      iden3comm.MediaType                      `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage                `json:"type"`
	ThreadID string                                   `json:"thid,omitempty"`
	Body     TransparentPaymentInstructionMessageBody `json:"body"`

	From string `json:"from"`
	To   string `json:"to"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`

	Attachments []iden3comm.Attachment `json:"attachments,omitempty"`
}

// TransparentPaymentInstructionMessageBody represents the body of the transparent payment instruction message
type TransparentPaymentInstructionMessageBody struct {
	GoalCode    string                 `json:"goal_code"`
	DID         string                 `json:"did,omitempty"`
	Credentials []CredentialSchemaInfo `json:"credentials"`
	PaymentData TransparentPaymentData `json:"paymentData"`
}

// CredentialSchemaInfo represents credential information in the transparent payment instruction
type CredentialSchemaInfo struct {
	Context string `json:"context"`
	Type    string `json:"type"`
}

// TransparentPaymentData represents payment data in the transparent payment instruction
type TransparentPaymentData struct {
	Type       string `json:"type"`
	Signature  string `json:"signature"`
	Recipient  string `json:"recipient"`
	Amount     string `json:"amount"`
	Token      string `json:"token,omitempty"`
	Expiration int64  `json:"expiration"`
	Nonce      uint64 `json:"nonce"`
	Metadata   string `json:"metadata,omitempty"`
}
