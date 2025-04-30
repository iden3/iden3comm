package protocol

import (
	"encoding/json"

	"github.com/iden3/iden3comm/v2"
)

const (
	// ProofGenerationRequestMessageType is type for request of proof generation
	ProofGenerationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "proofs/1.0/request"
	// ProofGenerationResponseMessageType is type for response of proof generation
	ProofGenerationResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "proofs/1.0/response"
)

// ProofGenerationRequestMessage is struct the represents body for proof generation request
// Deprecated: Removed from protocol
type ProofGenerationRequestMessage struct {
	iden3comm.BasicMessage
	Body ProofGenerationRequestMessageBody `json:"body,omitempty"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m ProofGenerationRequestMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *ProofGenerationRequestMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// ProofGenerationRequestMessageBody is struct the represents body for proof generation request
// Deprecated: Removed from protocol
type ProofGenerationRequestMessageBody struct {
	Scope []ZeroKnowledgeProofRequest `json:"scope"`
}

// ProofGenerationResponseMessage is struct the represents body for proof generation request
type ProofGenerationResponseMessage struct {
	iden3comm.BasicMessage
	Body ResponseMessageBody `json:"body,omitempty"`
}

// ResponseMessageBody is struct the represents request for revocation status
type ResponseMessageBody struct {
	Scope []ZeroKnowledgeProofResponse `json:"scope"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m ProofGenerationResponseMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *ProofGenerationResponseMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}
