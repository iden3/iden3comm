package iden3comm

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// MediaType is media type for iden3comm messages
type MediaType string

// BasicMessage is structure for message with unknown body format
type BasicMessage struct {
	ID       string          `json:"id"`
	Typ      MediaType       `json:"typ,omitempty"`
	Type     ProtocolMessage `json:"type"`
	ThreadID string          `json:"thid,omitempty"`
	Body     json.RawMessage `json:"body,omitempty"`

	From      string   `json:"from,omitempty"`
	To        string   `json:"-"`
	DIDCommTo []string `json:"-"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`

	Attachments []Attachment `json:"attachments,omitempty"`
}

type stringOrArray struct {
	to    string
	toArr []string
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (s *stringOrArray) UnmarshalJSON(bytes []byte) error {
	var a any
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	switch v := a.(type) {
	case []any:
		s.to = ""
		s.toArr = nil
		for _, k := range v {
			k2, ok := k.(string)
			if !ok {
				return errors.New("unexpected value")
			}
			s.toArr = append(s.toArr, k2)
		}
	case string:
		s.to = v
		s.toArr = nil
	}
	return nil
}

// UnmarshalJSON unmarhaler
func (m *BasicMessage) UnmarshalJSON(bytes []byte) error {

	var h struct {
		ID       string          `json:"id"`
		Typ      MediaType       `json:"typ,omitempty"`
		Type     ProtocolMessage `json:"type"`
		ThreadID string          `json:"thid,omitempty"`
		Body     json.RawMessage `json:"body,omitempty"`

		From        string        `json:"from,omitempty"`
		To          stringOrArray `json:"to"`
		CreatedTime *int64        `json:"created_time,omitempty"`
		ExpiresTime *int64        `json:"expires_time,omitempty"`

		Attachments []Attachment `json:"attachments,omitempty"`
	}

	err := json.Unmarshal(bytes, &h)
	if err != nil {
		return err
	}

	m.ID = h.ID
	m.Body = h.Body
	m.From = h.From
	m.CreatedTime = h.CreatedTime
	m.ExpiresTime = h.ExpiresTime
	m.ThreadID = h.ThreadID
	m.Typ = h.Typ
	m.Type = h.Type
	m.To = h.To.to
	m.DIDCommTo = h.To.toArr
	m.Attachments = h.Attachments

	return nil
}

// MarshalJSON - marshals basic protocol message with to field as an array or single string value
func (m BasicMessage) MarshalJSON() ([]byte, error) {

	var iden3comm struct {
		ID       string          `json:"id"`
		Typ      MediaType       `json:"typ,omitempty"`
		Type     ProtocolMessage `json:"type"`
		ThreadID string          `json:"thid,omitempty"`
		Body     json.RawMessage `json:"body,omitempty"`

		From        string `json:"from,omitempty"`
		CreatedTime *int64 `json:"created_time,omitempty"`
		ExpiresTime *int64 `json:"expires_time,omitempty"`
		To          string `json:"to,omitempty"`

		Attachments []Attachment `json:"attachments,omitempty"`
	}

	var didcomm struct {
		ID       string          `json:"id"`
		Typ      MediaType       `json:"typ,omitempty"`
		Type     ProtocolMessage `json:"type"`
		ThreadID string          `json:"thid,omitempty"`
		Body     json.RawMessage `json:"body,omitempty"`

		From        string   `json:"from,omitempty"`
		CreatedTime *int64   `json:"created_time,omitempty"`
		ExpiresTime *int64   `json:"expires_time,omitempty"`
		To          []string `json:"to,omitempty"`

		Attachments []Attachment `json:"attachments,omitempty"`
	}

	if m.DIDCommTo == nil {
		iden3comm.ID = m.ID
		iden3comm.Body = m.Body
		iden3comm.From = m.From
		iden3comm.CreatedTime = m.CreatedTime
		iden3comm.ExpiresTime = m.ExpiresTime
		iden3comm.ThreadID = m.ThreadID
		iden3comm.Typ = m.Typ
		iden3comm.Type = m.Type
		iden3comm.To = m.To
		iden3comm.Attachments = m.Attachments
		return json.Marshal(iden3comm)
	}
	didcomm.ID = m.ID
	didcomm.Body = m.Body
	didcomm.From = m.From
	didcomm.CreatedTime = m.CreatedTime
	didcomm.ExpiresTime = m.ExpiresTime
	didcomm.ThreadID = m.ThreadID
	didcomm.Typ = m.Typ
	didcomm.Type = m.Type

	didcomm.To = m.DIDCommTo
	didcomm.Attachments = m.Attachments

	return json.Marshal(didcomm)
}

// ProtocolMessage is IDEN3Comm message
type ProtocolMessage string

// Iden3Protocol is a const for protocol definition
const Iden3Protocol = "https://iden3-communication.io/"

// DidCommProtocol is a const for didcomm protocol definition
const DidCommProtocol = "https://didcomm.org/"
