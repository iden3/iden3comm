package protocol

import (
	"github.com/iden3/iden3comm/v2"
)

const (
	ProblemReportMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "report-problem/1.0/problem-report"
)

// ProblemReportMessage represent Iden3Message for problem report
type ProblemReportMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body ProblemReportMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// ProblemReportMessageBody is struct the represents body for problem report
// Code is an error code. Example
// Comment is a human-readable description of the problem. Directly related to the error code.
// Args is a list of strings that can be used to replace placeholders in the error message.
// EscalateTo is a string that can be used to escalate the problem to a human operator. It can be an email
type ProblemReportMessageBody struct {
	Code       ProblemErrorCode `json:"code"`
	Comment    string           `json:"comment,omitempty"`
	Args       []string         `json:"args,omitempty"`
	EscalateTo string           `json:"escalate_to,omitempty"`
}

// ProblemErrorCode is a string that represents the error code
type ProblemErrorCode string
