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

	// CredentialProposalRequestMessageType is type for request of the credential proposal
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialProposalRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/0.1/proposal-request"

	// CredentialProposalMessageType is type for proposal of the verifiable credential
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialProposalMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/0.1/proposal"

	// CredentialOfferStatusPending is a type when a credential issuance is in the process
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialOfferStatusPending = "pending"

	// CredentialOfferStatusCompleted if credential issuance is happened successfully
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialOfferStatusCompleted = "completed"

	// CredentialOfferStatusRejected - if credential issuance is not possible for some reason
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialOfferStatusRejected = "rejected"

	// CredentialProposalTypeWeb - if credential issuance is not possible for some reason
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialProposalTypeWeb = "WebVerificationFormV1.0"

	// CredentialPaymentRequestMessageType is type for request of the credential payment request
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialPaymentRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/0.1/payment-request"

	// CredentialPaymentMessageType is type for request of the credential payment
	//
	// # Experimental
	//
	// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
	CredentialPaymentMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/0.1/payment"

	// DiscoverFeatureQueriesMessageType is type for discover-features queries message
	DiscoverFeatureQueriesMessageType iden3comm.ProtocolMessage = iden3comm.DidCommProtocol + "discover-features/2.0/queries"

	// DiscoverFeatureDiscloseMessageType is type for discover-features disclose message
	DiscoverFeatureDiscloseMessageType iden3comm.ProtocolMessage = iden3comm.DidCommProtocol + "discover-features/2.0/disclose"
)

// CredentialIssuanceRequestMessage represent Iden3message for credential request
type CredentialIssuanceRequestMessage struct {
	iden3comm.BasicMessage
	Body CredentialIssuanceRequestMessageBody `json:"body,omitempty"`
}

// CredentialIssuanceRequestMessageBody represents data for credential issuance request
type CredentialIssuanceRequestMessageBody struct {
	Schema     Schema          `json:"schema"`
	Data       json.RawMessage `json:"data"`
	Expiration int64           `json:"expiration"`
}

// CredentialsOfferMessage represent Iden3message for credential offer
type CredentialsOfferMessage struct {
	iden3comm.BasicMessage
	Body CredentialsOfferMessageBody `json:"body,omitempty"`
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
	Status      string `json:"status,omitempty"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialsOfferMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialsOfferMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialIssuanceMessage represent Iden3message for credential issuance
type CredentialIssuanceMessage struct {
	iden3comm.BasicMessage
	Body IssuanceMessageBody `json:"body,omitempty"`
}

// IssuanceMessageBody is struct the represents message when credential is issued
type IssuanceMessageBody struct {
	Credential verifiable.W3CCredential `json:"credential"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialIssuanceMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialIssuanceMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialFetchRequestMessage represent Iden3message for credential fetch request
type CredentialFetchRequestMessage struct {
	iden3comm.BasicMessage
	Body CredentialFetchRequestMessageBody `json:"body,omitempty"`
}

// CredentialFetchRequestMessageBody is msg body for fetch request
type CredentialFetchRequestMessageBody struct {
	ID string `json:"id"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialFetchRequestMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialFetchRequestMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// Schema represents location and type where it's stored
type Schema struct {
	Hash string `json:"hash,omitempty"`
	URL  string `json:"url"`
	Type string `json:"type"`
}

// CredentialStatusUpdateMessage represents credential status update message
type CredentialStatusUpdateMessage struct {
	iden3comm.BasicMessage
	Body CredentialStatusUpdateMessageBody `json:"body,omitempty"`
}

// CredentialStatusUpdateMessageBody the structure that represents the body of credential status update message
type CredentialStatusUpdateMessageBody struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialStatusUpdateMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialStatusUpdateMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialRefreshMessage represent Iden3message for credential refresh message
type CredentialRefreshMessage struct {
	iden3comm.BasicMessage
	Body CredentialRefreshMessageBody `json:"body,omitempty"`
}

// CredentialRefreshMessageBody is msg body for refresh message
type CredentialRefreshMessageBody struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialRefreshMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON unmarshals protocol request message with typed body and basic structure
func (m *CredentialRefreshMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialsOnchainOfferMessage represent Iden3message for credential onchain offer
type CredentialsOnchainOfferMessage struct {
	iden3comm.BasicMessage
	Body CredentialsOnchainOfferMessageBody `json:"body,omitempty"`
}

// CredentialsOnchainOfferMessageBody is struct the represents onchain offer message
type CredentialsOnchainOfferMessageBody struct {
	Credentials     []CredentialOffer `json:"credentials"`
	TransactionData TransactionData   `json:"transaction_data"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialsOnchainOfferMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialsOnchainOfferMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialsProposalRequestMessage represent Iden3message for credential proposal request
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialsProposalRequestMessage struct {
	iden3comm.BasicMessage
	Body CredentialsProposalRequestBody `json:"body,omitempty"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialsProposalRequestMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialsProposalRequestMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialsProposalMessage represents Iden3message for credential proposal
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialsProposalMessage struct {
	iden3comm.BasicMessage
	Body CredentialsProposalBody `json:"body,omitempty"`
}

// CredentialsProposalRequestBody is msg body for proposal requests
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialsProposalRequestBody struct {
	Credentials []CredentialInfo `json:"credentials"`
	Metadata    *Metadata        `json:"metadata,omitempty"`
	DIDDoc      json.RawMessage  `json:"did_doc,omitempty"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialsProposalMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialsProposalMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialInfo is a part of credential proposal request bodys
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialInfo struct {
	Type    string `json:"type"`
	Context string `json:"context"`
}

// Metadata is metadata for credential proposal
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type Metadata struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// CredentialsProposalBody is a body for a credential proposal message
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialsProposalBody struct {
	Proposals []CredentialProposalInfo `json:"proposals"`
}

// CredentialProposalInfo is a info of specific proposal that can relate to many credentials
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialProposalInfo struct {
	Credentials []CredentialInfo `json:"credentials,omitempty"`
	Type        string           `json:"type"`
	URL         string           `json:"url"`
	Expiration  string           `json:"expiration,omitempty"`
	Description string           `json:"description,omitempty"`
}

// CredentialPaymentRequestMessage represent Iden3message for credential payment request
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialPaymentRequestMessage struct {
	iden3comm.BasicMessage
	Body CredentialPaymentRequestBody `json:"body,omitempty"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialPaymentRequestMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialPaymentRequestMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialPaymentRequestBody is msg body for payment requests
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialPaymentRequestBody struct {
	Agent    string                  `json:"agent"`
	Payments []CredentialPaymentInfo `json:"payments"`
}

// CredentialPaymentInfo is msg for payment information
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialPaymentInfo struct {
	Credentials []CredentialInfo      `json:"credentials"`
	Type        string                `json:"type"`
	Data        CredentialPaymentData `json:"data"`
	Expiration  string                `json:"expiration,omitempty"`
	Description string                `json:"description,omitempty"`
}

// CredentialPaymentData is msg for payment data
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialPaymentData struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Amount    string `json:"amount"`
	ChainID   string `json:"chainId"`
	Address   string `json:"address"`
	Signature string `json:"signature,omitempty"`
	Currency  string `json:"currency"`
}

// CredentialPaymentMessage represent Iden3message for credential payment
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialPaymentMessage struct {
	iden3comm.BasicMessage
	Body CredentialPaymentBody `json:"body,omitempty"`
}

// MarshalJSON marshals protocol request message with typed body and basic structure
func (m CredentialPaymentMessage) MarshalJSON() ([]byte, error) {
	return commonMarshal(m)
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (m *CredentialPaymentMessage) UnmarshalJSON(bytes []byte) error {

	err := json.Unmarshal(bytes, &m.BasicMessage)
	if err != nil {
		return err
	}
	return json.Unmarshal(m.BasicMessage.Body, &m.Body)
}

// CredentialPaymentBody is msg body for payment
//
// # Experimental
//
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.
type CredentialPaymentBody struct {
	Payments []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		PaymentData struct {
			TxID string `json:"txId"`
		} `json:"paymentData"`
	} `json:"payments"`
}
