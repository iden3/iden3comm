package protocol

import "github.com/iden3/iden3comm/v2"

const (
	// DeviceRegistrationRequestMessageType defines device registration request type of the communication protocol
	DeviceRegistrationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "devices/1.0/registration"
)

// DeviceRegistrationRequestMessage represent Iden3message for register device request
type DeviceRegistrationRequestMessage struct {
	iden3comm.BasicMessage
	Body DeviceRegistrationRequestMessageBody `json:"body,omitempty"`
}

// DeviceRegistrationRequestMessageBody is struct the represents body for register device request request
type DeviceRegistrationRequestMessageBody struct {
	AppID     string `json:"app_id"`
	PushToken string `json:"push_token"`
}
