package protocol

import (
	"encoding/json"

	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
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

	// CredentialStatusUpdateMessageType is type for message with a credential status update
	CredentialStatusUpdateMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/status-update"

	// CredentialRefreshMessageType is type for message with a credential refresh
	CredentialRefreshMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/refresh"

	// CredentialOnchainOfferMessageType is type for message with a credential onchain offer
	CredentialOnchainOfferMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/1.0/onchain-offer"
)

// CredentialIssuanceRequestMessage represent Iden3message for credential request
type CredentialIssuanceRequestMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body CredentialIssuanceRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialIssuanceRequestMessageBody represents data for credential issuance request
type CredentialIssuanceRequestMessageBody struct {
	Schema     Schema          `json:"schema"`
	Data       json.RawMessage `json:"data"`
	Expiration int64           `json:"expiration"`
}

// CredentialsOfferMessage represent Iden3message for credential offer
type CredentialsOfferMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body CredentialsOfferMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialsOfferMessageBody is struct the represents offer message
type CredentialsOfferMessageBody struct {
	URL         string            `json:"url"`
	Credentials []CredentialOffer `json:"credentials"`
}

// CredentialOffer is structure to fetch credential
type CredentialOffer struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// CredentialIssuanceMessage represent Iden3message for credential issuance
type CredentialIssuanceMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body IssuanceMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// IssuanceMessageBody is struct the represents message when credential is issued
type IssuanceMessageBody struct {
	Credential verifiable.W3CCredential `json:"credential"`
}

// CredentialFetchRequestMessage represent Iden3message for credential fetch request
type CredentialFetchRequestMessage struct {
	ID       string                            `json:"id"`
	Typ      iden3comm.MediaType               `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage         `json:"type"`
	ThreadID string                            `json:"thid,omitempty"`
	Body     CredentialFetchRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialFetchRequestMessageBody is msg body for fetch request
type CredentialFetchRequestMessageBody struct {
	ID string `json:"id"`
}

// Schema represents location and type where it's stored
type Schema struct {
	Hash string `json:"hash,omitempty"`
	URL  string `json:"url"`
	Type string `json:"type"`
}

// CredentialStatusUpdateMessage represents credential status update message
type CredentialStatusUpdateMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body CredentialStatusUpdateMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialStatusUpdateMessageBody the structure that represents the body of credential status update message
type CredentialStatusUpdateMessageBody struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// CredentialRefreshMessage represent Iden3message for credential refresh message
type CredentialRefreshMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body CredentialRefreshMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialRefreshMessageBody is msg body for refresh message
type CredentialRefreshMessageBody struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// CredentialsOnchainOfferMessage represent Iden3message for credential onchain offer
type CredentialsOnchainOfferMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body CredentialsOnchainOfferMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CredentialsOnchainOfferMessageBody is struct the represents onchain offer message
type CredentialsOnchainOfferMessageBody struct {
	Credentials     []CredentialOffer `json:"credentials"`
	TransactionData TransactionData   `json:"transaction_data"`
}
