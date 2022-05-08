package protocol

import (
	"github.com/iden3/iden3comm"
	"math/big"

	"github.com/iden3/go-schema-processor/verifiable"
)

const (

	// AuthorizationRequestMessageType defines auth request type of the communication protocol
	AuthorizationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/request"
	// AuthorizationResponseMessageType defines auth response type of the communication protocol
	AuthorizationResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/response"
)

// AuthorizationResponseMessage is struct the represents iden3message authorization response
type AuthorizationResponseMessage struct {
	Typ      iden3comm.MediaType              `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage        `json:"type"`
	ThreadID string                           `json:"thread_id,omitempty"`
	Body     AuthorizationMessageResponseBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// AuthorizationMessageResponseBody is struct the represents authorization response data
type AuthorizationMessageResponseBody struct {
	Scope []ZeroKnowledgeProofResponse `json:"scope"`
}

// AuthorizationRequestMessage is struct the represents iden3message authorization request
type AuthorizationRequestMessage struct {
	Typ      iden3comm.MediaType             `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage       `json:"type"`
	ThreadID string                          `json:"thread_id,omitempty"`
	Body     AuthorizationRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// AuthorizationRequestMessageBody is body for authorization request
type AuthorizationRequestMessageBody struct {
	CallbackURL string                      `json:"callbackUrl"`
	Audience    string                      `json:"audience"`
	Scope       []ZeroKnowledgeProofRequest `json:"scope"`
}

// ZeroKnowledgeProofRequest represents structure of zkp request object
type ZeroKnowledgeProofRequest struct {
	ID        string                 `json:"id"` //unique request id
	CircuitID string                 `json:"circuit_id"`
	Challenge *big.Int               `json:"challenge"`
	Rules     map[string]interface{} `json:"rules,omitempty"`
}

// ZeroKnowledgeProofResponse represents structure of zkp response
type ZeroKnowledgeProofResponse struct {
	ID        string `json:"id"` //unique id to present unique proof request
	CircuitID string `json:"circuit_id"`
	verifiable.ZKProof
}
