package iden3comm

import (
	"encoding/json"
)

// MediaType is media type for iden3comm messages
type MediaType string

// Iden3Message restricts objects that can be presented as protocol messages
type Iden3Message interface {
	GetMediaType() MediaType
	GetType() ProtocolMessage
	GetThreadID() string
	GetBody() interface{}
	GetFrom() string
	GetTo() string
}

// BasicMessage is structure for message with unknown body format
type BasicMessage struct {
	Typ      MediaType       `json:"typ,omitempty"`
	Type     ProtocolMessage `json:"type"`
	ThreadID string          `json:"thread_id,omitempty"`
	Body     json.RawMessage `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// GetType returns defined type of BasicMessage
func (m *BasicMessage) GetType() ProtocolMessage {
	return m.Type
}

// GetThreadID returns defined type of BasicMessage
func (m *BasicMessage) GetThreadID() string {
	return m.ThreadID
}

// GetBody returns body of BasicMessage
func (m *BasicMessage) GetBody() interface{} {
	return m.Body
}

// GetFrom returns data of BasicMessage
func (m *BasicMessage) GetFrom() string {
	return m.From
}

// GetTo returns data of BasicMessage
func (m *BasicMessage) GetTo() string {
	return m.To
}

// GetMediaType returns data of BasicMessage
func (m *BasicMessage) GetMediaType() MediaType {
	return m.Typ
}

// ProtocolMessage is IDEN3Comm message
type ProtocolMessage string

// Iden3Protocol is a const for protocol definition
const Iden3Protocol = "https://iden3-communication.io/"
