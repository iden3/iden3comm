package iden3comm

import "encoding/json"

// MediaType is media type for iden3comm messages
type MediaType string

// BasicMessage is structure for message with unknown body format
type BasicMessage struct {
	ID       string          `json:"id"`
	Typ      MediaType       `json:"typ,omitempty"`
	Type     ProtocolMessage `json:"type"`
	ThreadID string          `json:"thid,omitempty"`
	Body     json.RawMessage `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`
}

// ProtocolMessage is IDEN3Comm message
type ProtocolMessage string

// Iden3Protocol is a const for protocol definition
const Iden3Protocol = "https://iden3-communication.io/"

// DidCommProtocol is a const for didcomm protocol definition
const DidCommProtocol = "https://didcomm.org/"
