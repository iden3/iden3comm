package credentials

import (
	"context"
	"encoding/json"
	"github.com/iden3/iden3comm"

	"github.com/google/uuid"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/pkg/errors"
)

const (

	// Name of service
	Name = "credentials"

	// IssuanceRequestMessageType accepts request for credential creation
	IssuanceRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credential-issuance-request"

	// FetchRequestMessageType is type for request of credential generation
	FetchRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credential-fetch-request"

	// OfferMessageType is type of message with credential offering
	OfferMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credential-offer"

	// IssuanceResponseMessageType is type for message with a credential issuance
	IssuanceResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credential-issuance-response"
)

// Service for the revocation protocol.
type Service struct {
	ch creationHandler
	ih importHandler
	fh fetchHandler
}

type creationHandler interface {
	IssueCredential(ctx context.Context, issuer core.ID, subject core.ID, cReq []byte) (claimID string, err error)
}
type importHandler interface {
	ImportCredential(ctx context.Context, issuer core.ID, userID core.ID, cred verifiable.Iden3Credential) (err error)
}
type fetchHandler interface {
	FetchCredential(ctx context.Context, issuer core.ID, claimID uuid.UUID, req []byte) (cred *verifiable.Iden3Credential, err error)
}

type credManager interface {
	creationHandler
	importHandler
	fetchHandler
}

// New returns the revocation service.
func New(ch credManager) (*Service, error) {
	svc := Service{
		ch: ch,
	}

	return &svc, nil
}

// Name returns current name of service
func (s *Service) Name() string {
	return Name
}

// Accept is acceptance criteria for this basic message service.
func (s *Service) Accept(msgType iden3comm.ProtocolMessage) bool {
	return msgType == FetchRequestMessageType || msgType == IssuanceRequestMessageType || msgType == IssuanceResponseMessageType
}

// AcceptedMessages returns an array of accepted messages by service
func (s *Service) AcceptedMessages() []iden3comm.ProtocolMessage {
	return []iden3comm.ProtocolMessage{FetchRequestMessageType, IssuanceRequestMessageType, IssuanceResponseMessageType}
}

// Handle for basic message service.
func (s *Service) Handle(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	msgType := msg.GetType()

	if !s.Accept(msgType) {
		return nil, errors.Errorf("%s service doesn't accept messages with type %v", s.Name(), msgType)
	}

	switch msgType {
	case IssuanceRequestMessageType:
		return s.handleCreationRequest(ctx, msg)
	case FetchRequestMessageType:
		return s.handleFetchRequest(ctx, msg)
	case IssuanceResponseMessageType:
		return s.handleIssuanceMessage(ctx, msg)
	default:
		return nil, errors.Errorf("handler for message with type %v is not implemented", msgType)
	}
}

func (s *Service) handleFetchRequest(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	var fetchRequestBody CredentialFetchRequestMessageBody

	switch d := msg.GetBody().(type) {
	case json.RawMessage:
		err := json.Unmarshal(d, &fetchRequestBody)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case CredentialFetchRequestMessageBody:
		fetchRequestBody = d
	}

	if fetchRequestBody.ClaimID == "" {
		return nil, errors.New("no claim field in fetch request")
	}

	if fetchRequestBody.Schema.URL == "" {
		return nil, errors.New("no claim schema field in fetch request")
	}

	to := msg.GetTo()
	if to == "" {
		return nil, errors.New("no issuer is provided in 'to' field")
	}
	issuerID, err := core.IDFromString(to)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claimID, err := uuid.Parse(fetchRequestBody.ClaimID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	reqBytes, err := json.Marshal(fetchRequestBody)
	if err != nil {
		return nil, err
	}

	cred, err := s.fh.FetchCredential(ctx, issuerID, claimID, reqBytes)
	if err != nil {
		return nil, err
	}

	msgBody := IssuanceMessageBody{
		Credential: *cred,
	}
	marshaledBody, err := json.Marshal(msgBody)
	if err != nil {
		return nil, err
	}
	respMsg := iden3comm.BasicMessage{
		Type: IssuanceResponseMessageType,
		From: to,
		To:   cred.CredentialSubject["id"].(string),
		Body: marshaledBody,
	}

	return &respMsg, nil
}
func (s *Service) handleCreationRequest(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	var err error

	var credIssuanceReq CredentialIssuanceRequestMessageBody

	switch d := msg.GetBody().(type) {
	case json.RawMessage:
		err = json.Unmarshal(d, &credIssuanceReq)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case CredentialIssuanceRequestMessageBody:
		credIssuanceReq = d
	}

	to := msg.GetTo()
	if to == "" {
		return nil, errors.New("no issuer identity is provided in 'to' field")
	}

	subjectID, err := core.IDFromString(msg.GetFrom())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	issuerID, err := core.IDFromString(msg.GetTo())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	payload, err := json.Marshal(credIssuanceReq)
	if err != nil {
		return nil, err
	}
	claimID, err := s.ch.IssueCredential(ctx, issuerID, subjectID, payload)
	if err != nil {
		return nil, err
	}
	msgBody := OfferMessageBody{
		ClaimID: claimID,
		Schema: Schema{
			URL:  credIssuanceReq.Schema.URL,
			Type: credIssuanceReq.Schema.Type,
		},
	}

	marshaledBody, err := json.Marshal(msgBody)
	if err != nil {
		return nil, err
	}

	respMsg := iden3comm.BasicMessage{
		Type: OfferMessageType,
		From: issuerID.String(),
		To:   subjectID.String(),
		Body: marshaledBody,
	}

	return &respMsg, nil
}
func (s *Service) handleIssuanceMessage(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	var err error

	var credIssuanceMessage IssuanceMessageBody

	switch d := msg.GetBody().(type) {
	case json.RawMessage:
		err = json.Unmarshal(d, &credIssuanceMessage)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case IssuanceMessageBody:
		credIssuanceMessage = d
	}

	from := msg.GetFrom()
	if from == "" {
		return nil, errors.New("no issuer identity is provided in 'from' field")
	}

	to := msg.GetTo()
	if to == "" {
		return nil, errors.New("no subject identity is provided in 'to' field")
	}

	issuerID, err := core.IDFromString(msg.GetFrom())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	userID, err := core.IDFromString(msg.GetTo())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = s.ih.ImportCredential(ctx, issuerID, userID, credIssuanceMessage.Credential)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return nil, nil
}

// Schema represents location and type where it's stored
type Schema struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

// CredentialIssuanceRequestMessageBody represents data for credential issuance request
type CredentialIssuanceRequestMessageBody struct {
	Schema     Schema          `json:"schema"`
	Data       json.RawMessage `json:"data"`
	Expiration int64           `json:"expiration"`
}

// OfferMessageBody is struct the represents offer message
type OfferMessageBody struct {
	Schema  Schema `json:"schema"`
	ClaimID string `json:"claim_id"`
}

// IssuanceMessageBody is struct the represents message when credential is issued
type IssuanceMessageBody struct {
	Credential verifiable.Iden3Credential `json:"credential"`
}

// CredentialFetchRequestMessageBody is msg body for fetch request
type CredentialFetchRequestMessageBody struct {
	ClaimID string `json:"claim_id"`
	Schema  Schema `json:"schema"`
}
