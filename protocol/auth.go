package protocol

import (
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm"
)

const (

	// AuthorizationRequestMessageType defines auth request type of the communication protocol
	AuthorizationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/request"
	// AuthorizationV2RequestMessageType defines auth V2 request type of the communication protocol
	AuthorizationV2RequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/2.0/request"
	// AuthorizationResponseMessageType defines auth response type of the communication protocol
	AuthorizationResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/response"
)

// AuthorizationResponseMessage is struct the represents iden3message authorization response
type AuthorizationResponseMessage struct {
	ID       string                           `json:"id"`
	Typ      iden3comm.MediaType              `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage        `json:"type"`
	ThreadID string                           `json:"thid,omitempty"`
	Body     AuthorizationMessageResponseBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// AuthorizationMessageResponseBody is struct the represents authorization response data
type AuthorizationMessageResponseBody struct {
	Message string                       `json:"message,omitempty"`
	Scope   []ZeroKnowledgeProofResponse `json:"scope"`
}

// AuthorizationRequestMessage is struct the represents iden3message authorization request
type AuthorizationRequestMessage struct {
	ID       string                          `json:"id"`
	Typ      iden3comm.MediaType             `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage       `json:"type"`
	ThreadID string                          `json:"thid,omitempty"`
	Body     AuthorizationRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// AuthorizationRequestMessageBody is body for authorization request
type AuthorizationRequestMessageBody struct {
	CallbackURL string                      `json:"callbackUrl"`
	Reason      string                      `json:"reason,omitempty"`
	Message     string                      `json:"message,omitempty"`
	Scope       []ZeroKnowledgeProofRequest `json:"scope"`
}

// ZeroKnowledgeProofRequest represents structure of zkp request object
type ZeroKnowledgeProofRequest struct {
	ID        uint32                 `json:"id"` // unique request id
	CircuitID string                 `json:"circuit_id"`
	Optional  *bool                  `json:"optional,omitempty"`
	Rules     map[string]interface{} `json:"rules"`
}

// ZeroKnowledgeProofResponse represents structure of zkp response
type ZeroKnowledgeProofResponse struct {
	ID        uint32 `json:"id"` // unique id to present unique proof request
	CircuitID string `json:"circuit_id"`
	types.ZKProof
}
