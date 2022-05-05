package protocol

import (
	"encoding/json"
	"github.com/iden3/iden3comm"

	"github.com/iden3/go-schema-processor/verifiable"
)

const (

	// CredentialIssuanceRequestMessageType accepts request for credential creation
	CredentialIssuanceRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/issuance-request"

	// CredentialFetchRequestMessageType is type for request of credential generation
	CredentialFetchRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/fetch-request"

	// CredentialOfferMessageType is type of message with credential offering
	CredentialOfferMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/offer"

	// CredentialIssuanceResponseMessageType is type for message with a credential issuance
	CredentialIssuanceResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/issuance-response"
)

// CredentialIssuanceRequestMessage represent Iden3message for credential request
type CredentialIssuanceRequestMessage struct {
	Typ      iden3comm.MediaType                  `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage            `json:"type"`
	ThreadID string                               `json:"thread_id,omitempty"`
	Body     CredentialIssuanceRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialIssuanceRequestMessageBody represents data for credential issuance request
type CredentialIssuanceRequestMessageBody struct {
	Schema     Schema          `json:"schema"`
	Data       json.RawMessage `json:"data"`
	Expiration int64           `json:"expiration"`
}

// CredentialOfferMessage represent Iden3message for credential offer
type CredentialOfferMessage struct {
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thread_id,omitempty"`
	Body     OfferMessageBody          `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// OfferMessageBody is struct the represents offer message
type OfferMessageBody struct {
	Schema  Schema `json:"schema"`
	ClaimID string `json:"claim_id"`
}

// CredentialIssuanceMessage represent Iden3message for credential issuance
type CredentialIssuanceMessage struct {
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thread_id,omitempty"`
	Body     IssuanceMessageBody       `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// IssuanceMessageBody is struct the represents message when credential is issued
type IssuanceMessageBody struct {
	Credential verifiable.Iden3Credential `json:"credential"`
}

// CredentialFetchRequestMessage represent Iden3message for credential fetch
type CredentialFetchRequestMessage struct {
	Typ      iden3comm.MediaType               `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage         `json:"type"`
	ThreadID string                            `json:"thread_id,omitempty"`
	Body     CredentialFetchRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialFetchRequestMessageBody is msg body for fetch request
type CredentialFetchRequestMessageBody struct {
	ClaimID string `json:"claim_id"`
	Schema  Schema `json:"schema"`
}

// Schema represents location and type where it's stored
type Schema struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}
