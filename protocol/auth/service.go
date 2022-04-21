package auth

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/iden3comm"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/pkg/errors"
)

const (

	// Name represents name of the service
	Name = "authorization-service"
	// AuthorizationRequestMessageType defines auth request type of the communication protocol
	AuthorizationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/request"
	// AuthorizationResponseMessageType defines auth response type of the communication protocol
	AuthorizationResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/response"
)

// Service for the revocation protocol.
type Service struct {
}

// New returns the revocation service.
func New() (*Service, error) {
	svc := Service{}

	return &svc, nil
}

// Name returns current name of service
func (s *Service) Name() string {
	return Name
}

// Accept is acceptance criteria for this basic message service.
func (s *Service) Accept(msgType iden3comm.ProtocolMessage) bool {
	return msgType == AuthorizationResponseMessageType
}

// AcceptedMessages returns an array of accepted messages by service
func (s *Service) AcceptedMessages() []iden3comm.ProtocolMessage {
	return []iden3comm.ProtocolMessage{AuthorizationResponseMessageType}
}

// Handle for basic message service.
func (s *Service) Handle(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	msgType := msg.GetType()

	if !s.Accept(msgType) {
		return nil, errors.Errorf("%s service doesn't accept messages with type %v", s.Name(), msgType)
	}

	switch msgType {
	case AuthorizationResponseMessageType:
		return s.handleAuthorizationResponse(ctx, msg)
	default:
		return nil, errors.Errorf("handler for message with type %v is not implemented", msgType)
	}
}

func (s *Service) handleAuthorizationResponse(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	//var fetchRequestBody AuthorizationMessageResponseData
	//
	//switch d := msg.GetBody().(type) {
	//case json.RawMessage:
	//	err := json.Unmarshal(d, &fetchRequestBody)
	//	if err != nil {
	//		return nil, errors.WithStack(err)
	//	}
	//case CredentialFetchRequestMessageBody:
	//	fetchRequestBody = d
	//}
	//
	//if fetchRequestBody.ClaimID == "" {
	//	return nil, errors.New("no claim field in fetch request")
	//}
	//
	//if fetchRequestBody.Schema.URL == "" {
	//	return nil, errors.New("no claim schema field in fetch request")
	//}
	//
	//to := msg.GetTo()
	//if to == "" {
	//	return nil, errors.New("no issuer is provided in 'to' field")
	//}
	//issuerID, err := core.IDFromString(to)
	//if err != nil {
	//	return nil, errors.WithStack(err)
	//}
	//
	//claimID, err := uuid.Parse(fetchRequestBody.ClaimID)
	//if err != nil {
	//	return nil, errors.WithStack(err)
	//}
	//
	//reqBytes, err := json.Marshal(fetchRequestBody)
	//if err != nil {
	//	return nil, err
	//}
	//
	//cred, err := s.fh.FetchCredential(ctx, issuerID, claimID, reqBytes)
	//if err != nil {
	//	return nil, err
	//}
	//
	//msgBody := IssuanceMessageBody{
	//	Credential: *cred,
	//}
	//marshaledBody, err := json.Marshal(msgBody)
	//if err != nil {
	//	return nil, err
	//}
	//respMsg := iden3comm.BasicMessage{
	//	Type: IssuanceResponseMessageType,
	//	From: to,
	//	To:   cred.CredentialSubject["id"].(string),
	//	Body: marshaledBody,
	//}
	//
	//return &respMsg, nil
	return nil, nil
}

// AuthorizationMessageResponseData is struct the represents authorization response data
type AuthorizationMessageResponseBody struct {
	Scope []ZeroKnowledgeProof `json:"scope"`
}

// ZeroKnowledgeProof represents structure of zkp object
type ZeroKnowledgeProof struct {
	Type       verifiable.ProofType  `json:"type"`
	CircuitID  circuits.CircuitID    `json:"circuit_id"`
	PubSignals []string              `json:"pub_signals"`
	ProofData  *verifiable.ProofData `json:"proof_data"`
	ProofMetadata
}

// ProofMetadata defines basic metadata that can be retrieved from any proof
type ProofMetadata struct {
	AuthData       *AuthenticationMetadata `json:"auth_data,omitempty"`
	AdditionalData map[string]interface{}  `json:"additional_data,omitempty"`
}

// AuthenticationMetadata defines basic metadata that can be retrieved from auth proof
type AuthenticationMetadata struct {
	UserIdentifier          string
	UserState               string
	AuthenticationChallenge string
}
