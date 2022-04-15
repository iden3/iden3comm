package proof

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
	Name = "proof"
	// ProofGenerationRequest is type for request of proof generation
	ProofGenerationRequest iden3comm.ProtocolMessage = "https://iden3-communication.io/1.0/" + "proof-request"
	// ProofGenerationResponse is type for response of proof generation
	ProofGenerationResponse iden3comm.ProtocolMessage = "https://iden3-communication.io/1.0/" + "proof-response"
)

// zkProofService proof service interface
type proofGenerator interface {
	Generate(ctx context.Context,
		identifier *core.ID,
		request verifiable.ProofRequest) (*verifiable.ZKProof, error)
}

// Service for the revocation protocol.
type Service struct {
	pg proofGenerator
}

// New returns the revocation service.
func New(pg proofGenerator) (*Service, error) {
	svc := Service{
		pg: pg,
	}

	return &svc, nil
}

// Name returns current name of service
func (s *Service) Name() string {
	return Name
}

// Accept is acceptance criteria for this basic message service.
func (s *Service) Accept(msgType iden3comm.ProtocolMessage) bool {
	return msgType == ProofGenerationRequest
}

// AcceptedMessages returns an array of accepted messages by service
func (s *Service) AcceptedMessages() []iden3comm.ProtocolMessage {
	return []iden3comm.ProtocolMessage{ProofGenerationRequest}
}

// Handle for basic message service.
func (s *Service) Handle(ctx context.Context, msg iden3comm.Iden3Message) (iden3comm.Iden3Message, error) {

	var err error

	msgType := msg.GetType()

	if !s.Accept(msgType) {
		return nil, errors.Errorf("%s service doesn't accept messages with type %v", s.Name(), msgType)
	}

	var proofReqBody RequestMessageBody

	switch d := msg.GetBody().(type) {
	case json.RawMessage:
		err = json.Unmarshal(d, &proofReqBody)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case RequestMessageBody:
		proofReqBody = d
	}

	to := msg.GetTo()

	if to == "" {
		return nil, errors.New("no identity is provided in 'to' field")
	}

	from := msg.GetFrom()

	if from == "" {
		return nil, errors.New("no identity is provided in 'from' field")
	}

	id, err := core.IDFromString(msg.GetTo())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var respBody ResponseMessageBody
	respBody.Scope = make([]verifiable.ZKProof, 0)
	for _, r := range proofReqBody.Scope {
		proofResp, err := s.pg.Generate(ctx,&id,r)
		if err != nil{
			return nil, err
		}
		respBody.Scope = append(respBody.Scope,*proofResp)
	}

	marshaledBody, err := json.Marshal(respBody)
	if err != nil {
		return nil, err
	}

	respMsg := iden3comm.BasicMessage{
		Type: ProofGenerationResponse,
		Body: marshaledBody,
		From: to,
		To:   from,
	}

	return &respMsg, nil
}

// RequestMessageBody is struct the represents request for proof generation
type RequestMessageBody struct {
	Scope []verifiable.ProofRequest `json:"scope"`
}

// ResponseMessageBody is struct the represents request for revocation status
type ResponseMessageBody struct {
	Scope []verifiable.ZKProof `json:"scope"`
}
