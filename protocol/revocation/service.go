package revocation

import (
	"context"
	"encoding/json"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"

	"github.com/pkg/errors"
)

const (
	// Name of service
	Name = "revocation"
	// GetRevocationStatusMsgType is type for request of revocation status
	GetRevocationStatusMsgType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "request-revocation-status"
	// RevocationStatusMsgType is type for response with a revocation status
	RevocationStatusMsgType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation-status"
)

type nonRevocationProver interface {
	GetRevocationNonceMTP(ctx context.Context, issuerID *core.ID, nonce uint64) (*verifiable.RevocationStatus, error)
}

// Service for the revocation protocol.
type Service struct {
	pr nonRevocationProver
}

// New returns the revocation service.
func New(pr nonRevocationProver) (*Service, error) {
	svc := Service{
		pr: pr,
	}

	return &svc, nil
}

// Name returns current name of service
func (s *Service) Name() string {
	return Name
}

// Accept is acceptance criteria for this basic message service.
func (s *Service) Accept(msgType iden3comm.ProtocolMessage) bool {
	return msgType == GetRevocationStatusMsgType
}

// AcceptedMessages returns an array of accepted messages by service
func (s *Service) AcceptedMessages() []iden3comm.ProtocolMessage {
	return []iden3comm.ProtocolMessage{GetRevocationStatusMsgType}
}

// Handle for basic message service.
func (s *Service) Handle(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	var err error

	msgType := msg.GetType()

	if !s.Accept(msgType) {
		return nil, errors.Errorf("%s service doesn't accept messages with type %v", s.Name(), msgType)
	}

	var reqRevStatusBody RequestRevocationStatusMessageBody

	switch d := msg.GetBody().(type) {
	case json.RawMessage:
		err = json.Unmarshal(d, &reqRevStatusBody)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case RequestRevocationStatusMessageBody:
		reqRevStatusBody = d
	}

	to := msg.GetTo()

	if to == "" {
		return nil, errors.New("no identity is provided in 'to' field")
	}

	from := msg.GetFrom()

	if from == "" {
		return nil, errors.New("no identity is provided in 'from' field")
	}

	issuerID, err := core.IDFromString(to)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	proof, err := s.pr.GetRevocationNonceMTP(ctx, &issuerID, reqRevStatusBody.RevocationNonce)
	if err != nil {
		return nil, err
	}

	msgBody := ResponseRevocationStatusMessageBody{
		*proof,
	}
	marshaledBody, err := json.Marshal(msgBody)
	if err != nil {
		return nil, err
	}

	respMsg := iden3comm.BasicMessage{
		Type: RevocationStatusMsgType,
		Body: marshaledBody,
		From: to,
		To:   from,
	}

	return &respMsg, nil
}

// RequestRevocationStatusMessageBody is struct the represents request for revocation status
type RequestRevocationStatusMessageBody struct {
	RevocationNonce uint64 `json:"revocation_nonce"`
}

// ResponseRevocationStatusMessageBody is struct the represents request for revocation status
type ResponseRevocationStatusMessageBody struct {
	verifiable.RevocationStatus
}
