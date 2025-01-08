package iden3comm

import (
	"encoding/json"
)

// Iden3AttachmentType represents the type of attachment
type Iden3AttachmentType string

// Constants for Iden3AttachmentType
const (
	Iden3DirectiveAttachmentType Iden3AttachmentType = "Iden3Directive"
)

// Attachment is structure for message attachment
type Attachment struct {
	Type Iden3AttachmentType `json:"type"`
	Data any                 `json:"data"`
}

// Attachments is a slice of Attachment
type Attachments []*Attachment

// ExtractDirectives extracts directives from a given iden3comm.BasicMessage.
func (a *Attachments) ExtractDirectives() []Iden3Directive {

	if a == nil {
		return nil
	}

	var directives []Iden3Directive
	for _, attachment := range *a {
		if attachment.Type != Iden3DirectiveAttachmentType {
			continue
		}

		d := attachment.Data.([]Iden3Directive)

		directives = append(directives, d...)
	}

	return directives
}

// AddDirectives adds directive to attachments
func (a *Attachments) AddDirectives(d []Iden3Directive) {

	if len(d) == 0 {
		return
	}

	// find directive attachment
	for _, attachment := range *a {
		if attachment.Type == Iden3DirectiveAttachmentType {
			attachment.Data = append(attachment.Data.([]Iden3Directive), d...)
			return
		}
	}

	*a = append(*a, &Attachment{
		Type: Iden3DirectiveAttachmentType,
		Data: d,
	})
}

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

	CreatedTime *int64      `json:"created_time,omitempty"`
	ExpiresTime *int64      `json:"expires_time,omitempty"`
	Attachments Attachments `json:"attachments,omitempty"`
}

// ProtocolMessage is IDEN3Comm message
type ProtocolMessage string

// Iden3Protocol is a const for protocol definition
const Iden3Protocol = "https://iden3-communication.io/"

// DidCommProtocol is a const for didcomm protocol definition
const DidCommProtocol = "https://didcomm.org/"
