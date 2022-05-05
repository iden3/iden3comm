package protocol

import (
	"github.com/iden3/iden3comm"

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
	Scope []verifiable.ZKProof `json:"scope"`
}

// AuthorizationRequestMessage is struct the represents iden3message authorization request
type AuthorizationRequestMessage struct {
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thread_id,omitempty"`
	Body     AuthorizationRequestBody  `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// AuthorizationRequestBody is body for authorization request
type AuthorizationRequestBody struct {
	CallbackURL string                                 `json:"callbackUrl"`
	Audience    string                                 `json:"audience"`
	Scope       []verifiable.ZeroKnowledgeProofRequest `json:"scope"`
}
