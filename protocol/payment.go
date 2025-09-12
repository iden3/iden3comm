package protocol

import (
	"encoding/json"
	"fmt"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"

	"github.com/iden3/iden3comm/v2"
)

const (
	// PaymentRequestMessageType is a Iden3PaymentMessage payment type
	PaymentRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/0.1/payment-request"

	// PaymentMessageType is a Iden3PaymentMessage payment type
	PaymentMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "credentials/0.1/payment"

	// Iden3PaymentRequestCryptoV1Type is a Iden3PaymentRequestCryptoV1 payment type
	Iden3PaymentRequestCryptoV1Type PaymentRequestType = "Iden3PaymentRequestCryptoV1"

	// Iden3PaymentRailsRequestV1Type is a Iden3PaymentRailsRequestV1 payment type
	Iden3PaymentRailsRequestV1Type PaymentRequestType = "Iden3PaymentRailsRequestV1"

	// Iden3PaymentRailsERC20RequestV1Type is a Iden3PaymentRequestCryptoV1 payment type
	Iden3PaymentRailsERC20RequestV1Type PaymentRequestType = "Iden3PaymentRailsERC20RequestV1"

	// Iden3PaymentRailsSolanaRequestV1Type is a Iden3PaymentRailsSolanaRequestV1 payment type
	Iden3PaymentRailsSolanaRequestV1Type PaymentRequestType = "Iden3PaymentRailsSolanaRequestV1"

	// Iden3PaymentRailsSolanaSPLRequestV1Type is a Iden3PaymentRailsSolanaSPLRequestV1 payment type
	Iden3PaymentRailsSolanaSPLRequestV1Type PaymentRequestType = "Iden3PaymentRailsSolanaSPLRequestV1"

	// Iden3PaymentCryptoV1Type is a Iden3PaymentCryptoV1 payment type
	Iden3PaymentCryptoV1Type PaymentType = "Iden3PaymentCryptoV1"

	// Iden3PaymentRailsV1Type is a Iden3PaymentRailsV1 payment type
	Iden3PaymentRailsV1Type PaymentType = "Iden3PaymentRailsV1"

	// Iden3PaymentRailsERC20V1Type is a Iden3PaymentRailsERC20V1 payment type
	Iden3PaymentRailsERC20V1Type PaymentType = "Iden3PaymentRailsERC20V1"

	// Iden3PaymentRailsSolanaV1Type is a Iden3PaymentRailsSolanaV1 payment type
	Iden3PaymentRailsSolanaV1Type PaymentType = "Iden3PaymentRailsSolanaV1"

	// Iden3PaymentRailsSolanaSPLV1Type is a Iden3PaymentRailsSolanaSPLV1 payment type
	Iden3PaymentRailsSolanaSPLV1Type PaymentType = "Iden3PaymentRailsSolanaSPLV1"

	// SolanaEd25519Signature2025Type is a Solana Ed25519 signature proof type.
	SolanaEd25519Signature2025Type verifiable.ProofType = "SolanaEd25519Signature2025"
)

// PaymentType is type for Payment
type PaymentType string

// PaymentRequestType is type for Payment request
type PaymentRequestType string

// PaymentRequestMessage represents Iden3message for payment request.
type PaymentRequestMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body PaymentRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`

	Attachments []iden3comm.Attachment `json:"attachments,omitempty"`
}

// PaymentRequestMessageBody represents the body of the PaymentRequestMessage.
type PaymentRequestMessageBody struct {
	Agent    string               `json:"agent"`
	Payments []PaymentRequestInfo `json:"payments"`
}

// PaymentRequestInfo represents the payments request information.
type PaymentRequestInfo struct {
	Credentials []PaymentRequestInfoCredentials `json:"credentials"`
	Description string                          `json:"description"`
	Data        PaymentRequestInfoData          `json:"data"`
}

// PaymentRequestInfoData is a union type for field Data in PaymentRequestInfo.
type PaymentRequestInfoData []PaymentRequestInfoDataItem

// PaymentRequestInfoDataItem is the interface that any PaymentRequestInfoData.Data item must implement.
type PaymentRequestInfoDataItem interface {
	PaymentRequestType() PaymentRequestType
}

// MarshalJSON marshals the PaymentRequestInfoData into JSON.
func (p PaymentRequestInfoData) MarshalJSON() ([]byte, error) {
	if len(p) == 1 && p[0].PaymentRequestType() == Iden3PaymentRequestCryptoV1Type {
		return json.Marshal(p[0])
	}
	return json.Marshal([]PaymentRequestInfoDataItem(p))
}

// UnmarshalJSON unmarshal the PaymentRequestInfoData from JSON.
func (p *PaymentRequestInfoData) UnmarshalJSON(data []byte) error {
	type rawItem struct {
		Type PaymentRequestType `json:"type"`
	}

	var item rawItem
	var collection []json.RawMessage

	err := json.Unmarshal(data, &item)
	if err == nil {
		o, errItem := p.unmarshalFromItem(item.Type, data)
		if errItem != nil {
			return errItem
		}
		*p = append(*p, o)
		return nil
	}

	err = json.Unmarshal(data, &collection)
	if err != nil {
		return fmt.Errorf("PaymentRequestInfoData must be a PaymentRequestInfoDataItem or a collection: %w", err)
	}
	for n, rawItem := range collection {
		if err := json.Unmarshal(rawItem, &item); err != nil {
			return fmt.Errorf("field PaymentRequestInfoData[%d].Type not found: %w", n, err)
		}
		o, err := p.unmarshalFromItem(item.Type, rawItem)
		if err != nil {
			return err
		}
		*p = append(*p, o)
	}
	return nil
}

func (p *PaymentRequestInfoData) unmarshalFromItem(typ PaymentRequestType, data []byte) (PaymentRequestInfoDataItem, error) {
	switch typ {
	case Iden3PaymentRequestCryptoV1Type:
		var o Iden3PaymentRequestCryptoV1
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		return o, nil
	case Iden3PaymentRailsRequestV1Type:
		var o Iden3PaymentRailsRequestV1
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		return o, nil
	case Iden3PaymentRailsERC20RequestV1Type:
		var o Iden3PaymentRailsERC20RequestV1
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		return o, nil
	case Iden3PaymentRailsSolanaRequestV1Type:
		var o Iden3PaymentRailsSolanaRequestV1
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		return o, nil
	case Iden3PaymentRailsSolanaSPLRequestV1Type:
		var o Iden3PaymentRailsSolanaSPLRequestV1
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		return o, nil
	default:
		return nil, errors.Errorf("unmarshalling PaymentRequestInfoData. unknown type: %s", typ)
	}
}

// Iden3PaymentRequestCryptoV1 represents the Iden3PaymentRequestCryptoV1 payment request data.
type Iden3PaymentRequestCryptoV1 struct {
	Type       PaymentRequestType `json:"type"`
	ID         string             `json:"id"`
	Context    string             `json:"@context,omitempty"`
	ChainID    string             `json:"chainId"`
	Address    string             `json:"address"`
	Amount     string             `json:"amount"`
	Currency   string             `json:"currency"`
	Expiration string             `json:"expiration,omitempty"`
}

// PaymentRequestType implements the PaymentRequestInfoDataItem interface.
func (i Iden3PaymentRequestCryptoV1) PaymentRequestType() PaymentRequestType {
	return Iden3PaymentRequestCryptoV1Type
}

// Iden3PaymentRailsRequestV1 represents the Iden3PaymentRailsRequestV1 payment request data.
type Iden3PaymentRailsRequestV1 struct {
	Nonce          string             `json:"nonce"`
	Type           PaymentRequestType `json:"type"`
	Context        PaymentContext     `json:"@context"`
	Recipient      string             `json:"recipient"`
	Amount         string             `json:"amount"` // Not negative number
	ExpirationDate string             `json:"expirationDate"`
	Proof          PaymentProof       `json:"proof"`
	Metadata       string             `json:"metadata"`
}

// PaymentRequestType implements the PaymentRequestInfoDataItem interface.
func (i Iden3PaymentRailsRequestV1) PaymentRequestType() PaymentRequestType {
	return Iden3PaymentRailsRequestV1Type
}

// Iden3PaymentRailsERC20RequestV1 represents the Iden3PaymentRailsERC20RequestV1 payment request data.
type Iden3PaymentRailsERC20RequestV1 struct {
	Nonce          string             `json:"nonce"`
	Type           PaymentRequestType `json:"type"`
	Context        PaymentContext     `json:"@context"`
	Recipient      string             `json:"recipient"`
	Amount         string             `json:"amount"` // Not negative number
	ExpirationDate string             `json:"expirationDate"`
	Proof          PaymentProof       `json:"proof"`
	Metadata       string             `json:"metadata"`
	TokenAddress   string             `json:"tokenAddress"`
	Features       []PaymentFeatures  `json:"features,omitempty"`
}

// PaymentRequestType implements the PaymentRequestInfoDataItem interface.
func (i Iden3PaymentRailsERC20RequestV1) PaymentRequestType() PaymentRequestType {
	return Iden3PaymentRailsERC20RequestV1Type
}

// Iden3PaymentRailsSolanaRequestV1 represents the Iden3PaymentRailsSolanaRequestV1 payment request data.
type Iden3PaymentRailsSolanaRequestV1 struct {
	Nonce          string             `json:"nonce"`
	Type           PaymentRequestType `json:"type"`
	Context        PaymentContext     `json:"@context"`
	Recipient      string             `json:"recipient"`
	Amount         string             `json:"amount"` // Not negative number
	ExpirationDate string             `json:"expirationDate"`
	Proof          PaymentProof       `json:"proof"`
	Metadata       string             `json:"metadata"`
}

// PaymentRequestType implements the PaymentRequestInfoDataItem interface.
func (i Iden3PaymentRailsSolanaRequestV1) PaymentRequestType() PaymentRequestType {
	return Iden3PaymentRailsSolanaRequestV1Type
}

// Iden3PaymentRailsSolanaSPLRequestV1 represents the Iden3PaymentRailsSolanaSPLRequestV1 payment request data.
type Iden3PaymentRailsSolanaSPLRequestV1 struct {
	Nonce          string             `json:"nonce"`
	Type           PaymentRequestType `json:"type"`
	Context        PaymentContext     `json:"@context"`
	Recipient      string             `json:"recipient"`
	Amount         string             `json:"amount"` // Not negative number
	ExpirationDate string             `json:"expirationDate"`
	Proof          PaymentProof       `json:"proof"`
	Metadata       string             `json:"metadata"`
	TokenAddress   string             `json:"tokenAddress"`
	Features       []PaymentFeatures  `json:"features,omitempty"`
}

// PaymentRequestType implements the PaymentRequestInfoDataItem interface.
func (i Iden3PaymentRailsSolanaSPLRequestV1) PaymentRequestType() PaymentRequestType {
	return Iden3PaymentRailsSolanaSPLRequestV1Type
}

// PaymentFeatures represents type Features used in ERC20 payment request.
type PaymentFeatures string

// PaymentProof represents a payment proof.
type PaymentProof []PaymentProofItem

// PaymentProofItem is the interface that any PaymentProof item must implement.
type PaymentProofItem interface {
	PaymentProofItem() verifiable.ProofType
}

// UnmarshalJSON unmarshal the PaymentRequestInfoData from JSON.
func (p *PaymentProof) UnmarshalJSON(data []byte) error {
	var rawList []json.RawMessage

	// Try to unmarshal as an array
	if err := json.Unmarshal(data, &rawList); err != nil {
		// If not an array, try as a single object
		var single json.RawMessage
		if err := json.Unmarshal(data, &single); err != nil {
			return fmt.Errorf("failed to unmarshal proof data: %w", err)
		}
		rawList = []json.RawMessage{single}
	}

	for _, raw := range rawList {
		var typePeek struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &typePeek); err != nil {
			return fmt.Errorf("failed to detect proof type: %w", err)
		}

		var proof PaymentProofItem
		switch typePeek.Type {
		case string(document.EthereumEip712SignatureProof2021Type):
			var parsed EthereumEip712Signature2021
			if err := json.Unmarshal(raw, &parsed); err != nil {
				return fmt.Errorf("failed to unmarshal EthereumEip712Signature2021: %w", err)
			}
			proof = parsed

		case string(SolanaEd25519Signature2025Type):
			var parsed SolanaEd25519Signature2025
			if err := json.Unmarshal(raw, &parsed); err != nil {
				return fmt.Errorf("failed to unmarshal SolanaEd25519Signature2025: %w", err)
			}
			proof = parsed

		default:
			return fmt.Errorf("unsupported proof type: %s", typePeek.Type)
		}

		*p = append(*p, proof)
	}

	return nil
}

// MarshalJSON marshals the PaymentProof into JSON.
func (p PaymentProof) MarshalJSON() ([]byte, error) {
	return json.Marshal([]PaymentProofItem(p))
}

// EthereumEip712Signature2021 represents the Ethereum EIP712 signature.
type EthereumEip712Signature2021 struct {
	Type               verifiable.ProofType `json:"type"`
	ProofPurpose       string               `json:"proofPurpose"`
	ProofValue         string               `json:"proofValue"`
	VerificationMethod string               `json:"verificationMethod"`
	Created            string               `json:"created"`
	Eip712             Eip712Data           `json:"eip712"`
}

// PaymentProofItem implements the PaymentProofItem interface.
func (e EthereumEip712Signature2021) PaymentProofItem() verifiable.ProofType {
	return document.EthereumEip712SignatureProof2021Type
}

// SolanaEd25519Signature2025 represents represents Ed25519 signature for Solana Payment Instruction.
type SolanaEd25519Signature2025 struct {
	Type               verifiable.ProofType `json:"type"`
	ProofPurpose       string               `json:"proofPurpose"`
	ProofValue         string               `json:"proofValue"`
	VerificationMethod string               `json:"verificationMethod"`
	Created            string               `json:"created"`
	Domain             SolanaEd25519Domain  `json:"domain"`
}

// PaymentProofItem implements the PaymentProofItem interface.
func (e SolanaEd25519Signature2025) PaymentProofItem() verifiable.ProofType {
	return SolanaEd25519Signature2025Type
}

// Eip712Data represents the EIP712 data.
type Eip712Data struct {
	Types       string       `json:"types"`
	PrimaryType string       `json:"primaryType"`
	Domain      Eip712Domain `json:"domain"`
}

// Eip712Domain represents the EIP712 domain.
type Eip712Domain struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	ChainID           string `json:"chainId"`
	VerifyingContract string `json:"verifyingContract"`
}

// SolanaEd25519Domain represents the Solana EIP712 domain.
type SolanaEd25519Domain struct {
	Version           string `json:"version"`
	ChainID           string `json:"chainId"`
	VerifyingContract string `json:"verifyingContract"`
}

// PaymentRequestInfoCredentials represents the payment request credentials.
type PaymentRequestInfoCredentials struct {
	Context string `json:"context,omitempty"`
	Type    string `json:"type,omitempty"`
}

// PaymentMessage represents Iden3message for payment.
type PaymentMessage struct {
	iden3comm.BasicMessage
	Body PaymentMessageBody `json:"body,omitempty"`
}

// PaymentMessageBody represents the body of the PaymentMessage.
type PaymentMessageBody struct {
	Payments []Payment `json:"payments"`
}

// Payment is a union type for field Payments in PaymentMessageBody.
// Only one of the fields can be set at a time.
type Payment struct {
	dataType PaymentType
	crypto   *Iden3PaymentCryptoV1
	rails    *Iden3PaymentRailsV1
	railsERC *Iden3PaymentRailsERC20V1
}

// NewPaymentCrypto creates a new Payment with Iden3PaymentCryptoV1 data.
func NewPaymentCrypto(data Iden3PaymentCryptoV1) Payment {
	return Payment{
		dataType: Iden3PaymentCryptoV1Type,
		crypto:   &data,
	}
}

// NewPaymentRails creates a new Payment with Iden3PaymentRailsV1 data.
func NewPaymentRails(data Iden3PaymentRailsV1) Payment {
	return Payment{
		dataType: Iden3PaymentRailsV1Type,
		rails:    &data,
	}
}

// NewPaymentRailsERC20 creates a new Payment with Iden3PaymentRailsERC20V1 data.
func NewPaymentRailsERC20(data Iden3PaymentRailsERC20V1) Payment {
	return Payment{
		dataType: Iden3PaymentRailsERC20V1Type,
		railsERC: &data,
	}
}

// NewPaymentRailsSolana creates a new Payment with Iden3PaymentRailsSolanaV1 data.
func NewPaymentRailsSolana(data Iden3PaymentRailsSolanaV1) Payment {
	return Payment{
		dataType:    Iden3PaymentRailsSolanaV1Type,
		railsSolana: &data,
	}
}

// NewPaymentRailsSolanaSPL creates a new Payment with Iden3PaymentRailsSolanaSPLV1 data.
func NewPaymentRailsSolanaSPL(data Iden3PaymentRailsSolanaSPLV1) Payment {
	return Payment{
		dataType:       Iden3PaymentRailsSolanaSPLV1Type,
		railsSolanaSPL: &data,
	}
}

// Type returns the type of the data in the union. You can use Data() to get the data.
func (p *Payment) Type() PaymentType {
	return p.dataType
}

// Data returns the data in the union. You can use Type() to determine the type of the data.
func (p *Payment) Data() interface{} {
	switch p.dataType {
	case Iden3PaymentCryptoV1Type:
		return p.crypto
	case Iden3PaymentRailsV1Type:
		return p.rails
	case Iden3PaymentRailsERC20V1Type:
		return p.railsERC
	case Iden3PaymentRailsSolanaV1Type:
		return p.railsSolana
	case Iden3PaymentRailsSolanaSPLV1Type:
		return p.railsSolanaSPL
	}
	return nil
}

// UnmarshalJSON unmarshal the Payment from JSON.
func (p *Payment) UnmarshalJSON(bytes []byte) error {
	var item struct {
		Type PaymentType `json:"type"`
	}
	if err := json.Unmarshal(bytes, &item); err != nil {
		return fmt.Errorf("failed to unmarshal Payment: %w", err)
	}

	p.dataType = item.Type
	switch item.Type {
	case Iden3PaymentCryptoV1Type:
		return json.Unmarshal(bytes, &p.crypto)
	case Iden3PaymentRailsV1Type:
		return json.Unmarshal(bytes, &p.rails)
	case Iden3PaymentRailsERC20V1Type:
		return json.Unmarshal(bytes, &p.railsERC)
	case Iden3PaymentRailsSolanaV1Type:
		return json.Unmarshal(bytes, &p.railsSolana)
	case Iden3PaymentRailsSolanaSPLV1Type:
		return json.Unmarshal(bytes, &p.railsSolanaSPL)
	}
	return errors.Errorf("failed to unmarshal PaymentRequestInfoData: %s", string(bytes))
}

// MarshalJSON marshals the Payment into JSON.
func (p Payment) MarshalJSON() ([]byte, error) {
	switch p.dataType {
	case Iden3PaymentCryptoV1Type:
		return json.Marshal(p.crypto)
	case Iden3PaymentRailsV1Type:
		return json.Marshal(p.rails)
	case Iden3PaymentRailsERC20V1Type:
		return json.Marshal(p.railsERC)
	case Iden3PaymentRailsSolanaV1Type:
		return json.Marshal(p.railsSolana)
	case Iden3PaymentRailsSolanaSPLV1Type:
		return json.Marshal(p.railsSolanaSPL)
	}
	return nil, errors.New("failed to marshal not initialized Payment")
}

// Iden3PaymentCryptoV1 represents the Iden3PaymentCryptoV1 payment data.
type Iden3PaymentCryptoV1 struct {
	ID          string         `json:"id"`
	Type        PaymentType    `json:"type"`
	Context     PaymentContext `json:"@context,omitempty"`
	PaymentData struct {
		TxID string `json:"txId"`
	} `json:"paymentData"`
}

// Iden3PaymentRailsV1 represents the Iden3PaymentRailsV1 payment data.
type Iden3PaymentRailsV1 struct {
	Nonce       string         `json:"nonce"`
	Type        PaymentType    `json:"type"`
	Context     PaymentContext `json:"@context,omitempty"`
	PaymentData struct {
		TxID    string `json:"txId"`
		ChainID string `json:"chainId"`
	} `json:"paymentData"`
}

// Iden3PaymentRailsERC20V1 represents the Iden3PaymentRailsERC20V1 payment data.
type Iden3PaymentRailsERC20V1 struct {
	Nonce       string         `json:"nonce"`
	Type        PaymentType    `json:"type"`
	Context     PaymentContext `json:"@context,omitempty"`
	PaymentData struct {
		TxID         string `json:"txId"`
		ChainID      string `json:"chainId"`
		TokenAddress string `json:"tokenAddress"`
	} `json:"paymentData"`
}

// Iden3PaymentRailsSolanaV1 represents the Iden3PaymentRailsSolanaV1 payment data.
type Iden3PaymentRailsSolanaV1 Iden3PaymentRailsV1

// Iden3PaymentRailsSolanaSPLV1 represents the Iden3PaymentRailsSolanaSPLV1 payment data.
type Iden3PaymentRailsSolanaSPLV1 Iden3PaymentRailsERC20V1

// PaymentContext represents the payment context.
type PaymentContext struct {
	str     *string
	strCol  []string
	itemCol []interface{}
}

// NewPaymentContextString creates a new PaymentContext with a string.
func NewPaymentContextString(str ...string) PaymentContext {
	if len(str) == 1 {
		return PaymentContext{str: &str[0]}
	}
	return PaymentContext{strCol: str}
}

// NewPaymentContextItemCol creates a new PaymentContext with an interface{} collection.
func NewPaymentContextItemCol(itemCol ...interface{}) PaymentContext {
	return PaymentContext{itemCol: itemCol}
}

// MarshalJSON marshals the PaymentContext into JSON.
func (p PaymentContext) MarshalJSON() ([]byte, error) {
	if p.str != nil {
		return json.Marshal(p.str)
	}
	if len(p.strCol) != 0 {
		return json.Marshal(p.strCol)
	}
	if len(p.itemCol) != 0 {
		return json.Marshal(p.itemCol)
	}
	return nil, errors.New("failed to marshal not initialized PaymentContext")
}

// UnmarshalJSON unmarshal the PaymentContext from JSON.
func (p *PaymentContext) UnmarshalJSON(data []byte) error {
	var o any
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}

	switch v := o.(type) {
	case string:
		p.str = &v
		p.strCol = nil
		p.itemCol = nil
	case []any:
		p.str = nil
		p.itemCol = nil
		p.strCol = make([]string, len(v))
		for i := range v {
			s, ok := v[i].(string)
			if !ok {
				p.strCol = nil
				p.itemCol = v
				break
			}
			p.strCol[i] = s
		}
	default:
		return errors.Errorf("failed to unmarshal PaymentContext: %s", string(data))
	}

	return nil
}

// Data returns the data in the union.
func (p PaymentContext) Data() interface{} {
	if p.str != nil {
		return p.str
	}
	if len(p.strCol) != 0 {
		return p.strCol
	}
	if len(p.itemCol) != 0 {
		return p.itemCol
	}
	return nil
}
