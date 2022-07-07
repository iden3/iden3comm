package protocol

import "github.com/iden3/iden3comm"

const (
	// RegisterDeviceRequestMessageType defines register device request type of the communication protocol
	RegisterDeviceRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "devices/1.0/registration"
)

// RegisterDeviceRequestMessage represent Iden3message for register device request
type RegisterDeviceRequestMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body RegisterDeviceRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// RegisterDeviceRequestMessageBody is struct the represents body for register device request request
type RegisterDeviceRequestMessageBody struct {
	AppID  string `json:"app_id"`
	PushToken  string `json:"push_token"`
}
