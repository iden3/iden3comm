package iden3comm

// Iden3DirectiveType represents the type of directive
type Iden3DirectiveType string

// Constants for Iden3DirectiveType
const (
	TransparentPaymentDirectiveType Iden3DirectiveType = "TransparentPaymentDirective"
)

// TransparentPaymentCredential represents credential information
type TransparentPaymentCredential struct {
	Type    string `json:"type"`
	Context string `json:"context"`
}

// TransparentPaymentRequestData represents payment request information
type TransparentPaymentRequestData struct {
	Recipient  string `json:"recipient"`
	Amount     string `json:"amount"`
	Token      string `json:"token,omitempty"`
	Expiration string `json:"expiration"`
	Nonce      string `json:"nonce"`
	Metadata   string `json:"metadata"`
}

// TransparentPaymentDirectivePayload represents the payload for a transparent payment directive
type TransparentPaymentDirectivePayload struct {
	Credential      TransparentPaymentCredential  `json:"credential"`
	PaymentData     TransparentPaymentRequestData `json:"paymentData"`
	PermitSignature string                        `json:"permitSignature"`
	Description     string                        `json:"description,omitempty"`
}

// TransparentPaymentDirective represents a complete transparent payment directive
type TransparentPaymentDirective struct {
	Type    Iden3DirectiveType                   `json:"type"`
	Purpose ProtocolMessage                      `json:"purpose,omitempty"`
	Context string                               `json:"context,omitempty"`
	Data    []TransparentPaymentDirectivePayload `json:"data"`
}

// Iden3Directive is currently an alias for TransparentPaymentDirective
// Can be expanded to a union type using interfaces if more directive types are added
type Iden3Directive = TransparentPaymentDirective
