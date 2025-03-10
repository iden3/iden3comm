// Package protocol defines core protocol messages
package protocol

import (
	"encoding/json"

	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm/v2"
)

const (

	// AuthorizationRequestMessageType defines auth request type of the communication protocol
	AuthorizationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/request"
	// AuthorizationResponseMessageType defines auth response type of the communication protocol
	AuthorizationResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/response"
)

// AuthorizationResponseMessage is struct the represents iden3message authorization response
type AuthorizationResponseMessage struct {
	iden3comm.BasicMessage
	Body AuthorizationMessageResponseBody `json:"body,omitempty"`
}

// AuthorizationMessageResponseBody is struct the represents authorization response data
type AuthorizationMessageResponseBody struct {
	DIDDoc  json.RawMessage              `json:"did_doc,omitempty"`
	Message string                       `json:"message,omitempty"`
	Scope   []ZeroKnowledgeProofResponse `json:"scope"`
}

// MarshalJSON is
func (m AuthorizationResponseMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON is
func (m *AuthorizationResponseMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// AuthorizationRequestMessage is struct the represents iden3message authorization request
type AuthorizationRequestMessage struct {
	iden3comm.BasicMessage
	Body AuthorizationRequestMessageBody `json:"body,omitempty"`
}

// MarshalJSON is
func (m AuthorizationRequestMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON is
func (m *AuthorizationRequestMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// AuthorizationRequestMessageBody is body for authorization request
type AuthorizationRequestMessageBody struct {
	CallbackURL string                      `json:"callbackUrl"`
	Reason      string                      `json:"reason,omitempty"`
	Message     string                      `json:"message,omitempty"`
	DIDDoc      json.RawMessage             `json:"did_doc,omitempty"`
	Scope       []ZeroKnowledgeProofRequest `json:"scope"`
	Accept      []string                    `json:"accept,omitempty"`
}

// ZeroKnowledgeProofRequest represents structure of zkp request object
type ZeroKnowledgeProofRequest struct {
	ID        uint32                 `json:"id"` // unique request id
	CircuitID string                 `json:"circuitId"`
	Params    map[string]interface{} `json:"params,omitempty"`
	Optional  *bool                  `json:"optional,omitempty"`
	Query     map[string]interface{} `json:"query"`
}

// ZeroKnowledgeProofResponse represents structure of zkp response
type ZeroKnowledgeProofResponse struct {
	ID                     uint32          `json:"id"` // unique id to present unique proof request
	CircuitID              string          `json:"circuitId"`
	VerifiablePresentation json.RawMessage `json:"vp,omitempty"`
	types.ZKProof
}
