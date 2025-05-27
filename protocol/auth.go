// Package protocol defines core protocol messages
package protocol

import (
	"encoding/json"
	"math/big"

	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm/v2"
	"github.com/pkg/errors"
)

const (

	// AuthorizationRequestMessageType defines auth request type of the communication protocol
	AuthorizationRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/request"
	// AuthorizationResponseMessageType defines auth response type of the communication protocol
	AuthorizationResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "authorization/1.0/response"
)

// AuthorizationResponseMessage is struct the represents iden3message authorization response
type AuthorizationResponseMessage struct {
	ID       string                           `json:"id"`
	Typ      iden3comm.MediaType              `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage        `json:"type"`
	ThreadID string                           `json:"thid,omitempty"`
	Body     AuthorizationMessageResponseBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`
}

// AuthorizationMessageResponseBody is struct the represents authorization response data
type AuthorizationMessageResponseBody struct {
	DIDDoc  json.RawMessage              `json:"did_doc,omitempty"`
	Message string                       `json:"message,omitempty"`
	Scope   []ZeroKnowledgeProofResponse `json:"scope"`
}

// AuthorizationRequestMessage is struct the represents iden3message authorization request
type AuthorizationRequestMessage struct {
	ID       string                          `json:"id"`
	Typ      iden3comm.MediaType             `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage       `json:"type"`
	ThreadID string                          `json:"thid,omitempty"`
	Body     AuthorizationRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`
}

// AuthorizationRequestMessageBody is body for authorization request
type AuthorizationRequestMessageBody struct {
	CallbackURL string                      `json:"callbackUrl"`
	Reason      string                      `json:"reason,omitempty"`
	Message     string                      `json:"message,omitempty"`
	DIDDoc      json.RawMessage             `json:"did_doc,omitempty"`
	Scope       []ZeroKnowledgeProofRequest `json:"scope"`
	Accept      []string                    `json:"accept,omitempty"`
}

// ZeroKnowledgeProofRequest represents structure of zkp request object
type ZeroKnowledgeProofRequest struct {
	ID         uint32
	CircuitID  string                 `json:"circuitId"`
	Params     map[string]interface{} `json:"params,omitempty"`
	Optional   *bool                  `json:"optional,omitempty"`
	Query      map[string]interface{} `json:"query"`
	ExtendedID *big.Int
}

// MarshalJSON - marshals the protocol zero-knowledge proof request depending on ID or ExtendedID value
func (r ZeroKnowledgeProofRequest) MarshalJSON() ([]byte, error) {

	var zkRequest struct {
		ID        numberish              `json:"id"` // unique request id
		CircuitID string                 `json:"circuitId"`
		Params    map[string]interface{} `json:"params,omitempty"`
		Optional  *bool                  `json:"optional,omitempty"`
		Query     map[string]interface{} `json:"query"`
	}
	if r.ExtendedID != nil && r.ID != 0 {
		return nil, errors.New("only one field for ZeroKnowledgeProofRequest must be initiated, ExtendedID or ID")
	}
	if r.ExtendedID != nil {
		zkRequest.ID.bigIntValue = r.ExtendedID
	} else {
		zkRequest.ID.uint32value = r.ID
	}

	zkRequest.CircuitID = r.CircuitID
	zkRequest.Params = r.Params
	zkRequest.Optional = r.Optional
	zkRequest.Query = r.Query

	return json.Marshal(zkRequest)
}

// UnmarshalJSON unmarhaler
func (r *ZeroKnowledgeProofRequest) UnmarshalJSON(bytes []byte) error {

	var zkRequest struct {
		ID        numberish              `json:"id"` // unique request id
		CircuitID string                 `json:"circuitId"`
		Params    map[string]interface{} `json:"params,omitempty"`
		Optional  *bool                  `json:"optional,omitempty"`
		Query     map[string]interface{} `json:"query"`
	}

	err := json.Unmarshal(bytes, &zkRequest)
	if err != nil {
		return err
	}

	// check if written integer is more than uint32
	if zkRequest.ID.bigIntValue != nil {
		r.ExtendedID = zkRequest.ID.bigIntValue
	} else {
		r.ID = zkRequest.ID.uint32value
	}
	r.CircuitID = zkRequest.CircuitID
	r.Query = zkRequest.Query
	r.Optional = zkRequest.Optional
	r.Params = zkRequest.Params

	return nil
}

// ZeroKnowledgeProofResponse represents structure of zkp response
type ZeroKnowledgeProofResponse struct {
	ID                     uint32
	ExtendedID             *big.Int
	CircuitID              string          `json:"circuitId"`
	VerifiablePresentation json.RawMessage `json:"vp,omitempty"`
	types.ZKProof
}

// MarshalJSON - marshals the protocol zero-knowledge proof response depending on ID or ExtendedID value
func (r ZeroKnowledgeProofResponse) MarshalJSON() ([]byte, error) {

	var zkResponse struct {
		ID                     numberish       `json:"id"`
		CircuitID              string          `json:"circuitId"`
		VerifiablePresentation json.RawMessage `json:"vp,omitempty"`
		types.ZKProof
	}
	if r.ExtendedID != nil && r.ID != 0 {
		return nil, errors.New("only one field for ZeroKnowledgeProofResponse must be initiated, ExtendedID or ID ")
	}
	if r.ExtendedID != nil {
		zkResponse.ID.bigIntValue = r.ExtendedID
	} else {
		zkResponse.ID.uint32value = r.ID
	}

	zkResponse.CircuitID = r.CircuitID
	zkResponse.VerifiablePresentation = r.VerifiablePresentation
	zkResponse.ZKProof = r.ZKProof

	return json.Marshal(zkResponse)
}

// UnmarshalJSON unmarhaler
func (r *ZeroKnowledgeProofResponse) UnmarshalJSON(bytes []byte) error {

	var zkResponse struct {
		ID                     numberish       `json:"id"`
		CircuitID              string          `json:"circuitId"`
		VerifiablePresentation json.RawMessage `json:"vp,omitempty"`
		types.ZKProof
	}

	err := json.Unmarshal(bytes, &zkResponse)
	if err != nil {
		return err
	}

	if zkResponse.ID.bigIntValue != nil {
		r.ExtendedID = zkResponse.ID.bigIntValue
	} else {
		r.ID = zkResponse.ID.uint32value
	}

	r.CircuitID = zkResponse.CircuitID
	r.VerifiablePresentation = zkResponse.VerifiablePresentation
	r.ZKProof = zkResponse.ZKProof

	return nil
}

type numberish struct {
	uint32value uint32
	bigIntValue *big.Int
}

// UnmarshalJSON  unmarshals protocol request message with typed body and basic structure
func (n *numberish) UnmarshalJSON(bytes []byte) error {

	var num uint32
	if err := json.Unmarshal(bytes, &num); err == nil {
		n.uint32value = num
		n.bigIntValue = nil
		return nil
	}

	var s string
	if err := json.Unmarshal(bytes, &s); err == nil {
		bi := new(big.Int)
		if _, ok := bi.SetString(s, 10); ok {
			n.bigIntValue = bi
			n.uint32value = 0
			return nil
		}
		return errors.New("invalid big.Int string format")
	}

	return errors.New("unsupported format, expected uint32 as number or bigInt as string")
}

// MarshalJSON - marshals the protocol zero-knowledge proof response depending on ID or ExtendedID value
func (n numberish) MarshalJSON() ([]byte, error) {
	if n.bigIntValue != nil {
		return json.Marshal(n.bigIntValue.String())
	}
	return json.Marshal(n.uint32value)
}
