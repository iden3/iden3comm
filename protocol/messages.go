package protocol

import (
	"encoding/json"

	"github.com/iden3/iden3comm/v2"
)

const (
	// MessageFetchRequestMessageType defines message fetch request type of the communication protocol.
	MessageFetchRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "messages/1.0/fetch"
)

// MessageFetchRequestMessage represent Iden3message for message fetch request.
// Deprecated: Removed from protocol
type MessageFetchRequestMessage struct {
	iden3comm.BasicMessage
	Body MessageFetchRequestMessageBody `json:"body,omitempty"`
}

// MessageFetchRequestMessageBody is struct the represents body for message fetch request.
type MessageFetchRequestMessageBody struct {
	ID string `json:"id"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m MessageFetchRequestMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *MessageFetchRequestMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}
