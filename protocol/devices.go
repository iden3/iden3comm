package protocol

import (
	"encoding/json"

	"github.com/iden3/iden3comm/v2"
)

const (
	// DeviceRegistrationRequestMessageType defines device registration request type of the communication protocol
	DeviceRegistrationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "devices/1.0/registration"
)

// DeviceRegistrationRequestMessage represent Iden3message for register device request
// Deprecated: Removed from protocol
type DeviceRegistrationRequestMessage struct {
	iden3comm.BasicMessage
	Body DeviceRegistrationRequestMessageBody `json:"body,omitempty"`
}

// DeviceRegistrationRequestMessageBody is struct the represents body for register device request request
type DeviceRegistrationRequestMessageBody struct {
	AppID     string `json:"app_id"`
	PushToken string `json:"push_token"`
}

// MarshalJSON is
func (m DeviceRegistrationRequestMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON is
func (m *DeviceRegistrationRequestMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}
