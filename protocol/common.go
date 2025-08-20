package protocol

import (
	"fmt"

	"github.com/iden3/iden3comm/v2"
)

// GoalCode represents the goal code of targeted protocol message
type GoalCode string

const (
	// ProposalRequest is the goal code for proposal request
	ProposalRequest GoalCode = "iden3comm.credentials.v1-1.proposal-request"
)

// GetProtocolMessageTypeByGoalCode returns the protocol message type by goal code
func GetProtocolMessageTypeByGoalCode(goalCode GoalCode) (iden3comm.ProtocolMessage, error) {
	switch goalCode {
	case ProposalRequest:
		return CredentialProposalRequestMessageType, nil
	default:
		return "", fmt.Errorf("unknown goal code %s", goalCode)
	}
}
