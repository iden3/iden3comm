package iden3comm

// Attachment represents a DIDComm message attachment
type Attachment struct {
	ID          string     `json:"id"`
	Description string     `json:"description,omitempty"`
	MediaType   MediaType  `json:"media_type"`
	Data        AttachData `json:"data"`
}

// AttachData represents the data field in a DIDComm attachment
type AttachData struct {
	JSON interface{} `json:"json,omitempty"`
	// Future fields can be added here:
	// JWS  interface{} `json:"jws,omitempty"`
	// Hash interface{} `json:"hash,omitempty"`
	// Link interface{} `json:"link,omitempty"`
}
