package protocol

import (
	"encoding/json"
	"fmt"

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
	Iden3PaymentRequestCryptoV1Type = "Iden3PaymentRequestCryptoV1"

	// Iden3PaymentRailsRequestV1Type is a Iden3PaymentRailsRequestV1 payment type
	Iden3PaymentRailsRequestV1Type = "Iden3PaymentRailsRequestV1"

	// Iden3PaymentRailsERC20RequestV1Type is a Iden3PaymentRequestCryptoV1 payment type
	Iden3PaymentRailsERC20RequestV1Type = "Iden3PaymentRailsERC20RequestV1"

	// Iden3PaymentCryptoV1Type is a Iden3PaymentCryptoV1 payment type
	Iden3PaymentCryptoV1Type = "Iden3PaymentCryptoV1"

	// Iden3PaymentRailsV1Type is a Iden3PaymentRailsV1 payment type
	Iden3PaymentRailsV1Type = "Iden3PaymentRailsV1"

	// Iden3PaymentRailsERC20V1Type is a Iden3PaymentRailsERC20V1 payment type
	Iden3PaymentRailsERC20V1Type = "Iden3PaymentRailsERC20V1"
)

// PaymentRequestMessage represents Iden3message for payment request.
type PaymentRequestMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body PaymentRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// PaymentRequestMessageBody represents the body of the PaymentRequestMessage.
type PaymentRequestMessageBody struct {
	Agent    string               `json:"agent"`
	Payments []PaymentRequestInfo `json:"payments"`
}

// PaymentRequestInfo represents the payments request information.
type PaymentRequestInfo struct {
	Type        string                          `json:"type,omitempty"`
	Credentials []PaymentRequestInfoCredentials `json:"credentials"`
	Description string                          `json:"description"`
	Data        PaymentRequestInfoData          `json:"data"`
}

// PaymentRequestInfoData is a union type for field Data in PaymentRequestInfo.
// Only one of the fields can be set at a time.
type PaymentRequestInfoData struct {
	dataType string
	crypto   []Iden3PaymentRequestCryptoV1
	rails    []Iden3PaymentRailsRequestV1
	railsERC []Iden3PaymentRailsERC20RequestV1
}

// NewPaymentRequestInfoDataCrypto creates a new PaymentRequestInfoData with Iden3PaymentRequestCryptoV1 data.
func NewPaymentRequestInfoDataCrypto(data Iden3PaymentRequestCryptoV1) PaymentRequestInfoData {
	return PaymentRequestInfoData{
		dataType: Iden3PaymentRequestCryptoV1Type,
		crypto:   []Iden3PaymentRequestCryptoV1{data},
	}
}

// NewPaymentRequestInfoDataRails creates a new PaymentRequestInfoData with Iden3PaymentRailsRequestV1 data.
func NewPaymentRequestInfoDataRails(data Iden3PaymentRailsRequestV1) PaymentRequestInfoData {
	return PaymentRequestInfoData{
		dataType: Iden3PaymentRailsRequestV1Type,
		rails:    []Iden3PaymentRailsRequestV1{data},
	}
}

// NewPaymentRequestInfoDataRailsERC20 creates a new PaymentRequestInfoData with Iden3PaymentRailsERC20RequestV1 data.
func NewPaymentRequestInfoDataRailsERC20(data Iden3PaymentRailsERC20RequestV1) PaymentRequestInfoData {
	return PaymentRequestInfoData{
		dataType: Iden3PaymentRailsERC20RequestV1Type,
		railsERC: []Iden3PaymentRailsERC20RequestV1{data},
	}
}

// Type returns the type of the data in the union. You can use Data() to get the data.
func (p *PaymentRequestInfoData) Type() string {
	return p.dataType
}

// Data returns the data in the union. You can use Type() to determine the type of the data.
func (p *PaymentRequestInfoData) Data() interface{} {
	switch p.dataType {
	case Iden3PaymentRequestCryptoV1Type:
		return p.crypto
	case Iden3PaymentRailsRequestV1Type:
		return p.rails
	case Iden3PaymentRailsERC20RequestV1Type:
		return p.railsERC
	}
	return nil
}

// MarshalJSON marshals the PaymentRequestInfoData into JSON.
func (p PaymentRequestInfoData) MarshalJSON() ([]byte, error) {
	switch p.dataType {
	case Iden3PaymentRequestCryptoV1Type:
		return json.Marshal(p.crypto[0])
	case Iden3PaymentRailsRequestV1Type:
		return json.Marshal(p.rails)
	case Iden3PaymentRailsERC20RequestV1Type:
		return json.Marshal(p.railsERC)
	}
	return nil, errors.New("failed to marshal not initialized PaymentRequestInfoData")
}

// UnmarshalJSON unmarshal the PaymentRequestInfoData from JSON.
func (p *PaymentRequestInfoData) UnmarshalJSON(data []byte) error {
	var item struct {
		Type string `json:"type"`
	}
	var collection []struct {
		Type string `json:"type"`
	}

	p.crypto, p.rails, p.railsERC = nil, nil, nil

	if err := json.Unmarshal(data, &item); err == nil {
		p.dataType = item.Type
		return p.unmarshalFromItem(item.Type, data)
	}

	if err := json.Unmarshal(data, &collection); err == nil {
		if len(collection) == 0 {
			return nil
		}

		p.dataType = collection[0].Type
		return p.unmarshalFromCollection(p.dataType, data)
	}
	return errors.New("failed to unmarshal PaymentRequestInfoData. not a single item nor a collection")
}

func (p *PaymentRequestInfoData) unmarshalFromItem(typ string, data []byte) error {
	switch typ {
	case Iden3PaymentRequestCryptoV1Type:
		var o Iden3PaymentRequestCryptoV1
		if err := json.Unmarshal(data, &o); err != nil {
			return fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		p.crypto = []Iden3PaymentRequestCryptoV1{o}
	case Iden3PaymentRailsRequestV1Type:
		var o Iden3PaymentRailsRequestV1
		if err := json.Unmarshal(data, &o); err != nil {
			return fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		p.rails = []Iden3PaymentRailsRequestV1{o}
	case Iden3PaymentRailsERC20RequestV1Type:
		var o Iden3PaymentRailsERC20RequestV1
		if err := json.Unmarshal(data, &o); err != nil {
			return fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
		p.railsERC = []Iden3PaymentRailsERC20RequestV1{o}
	default:
		return errors.Errorf("unmarshalling PaymentRequestInfoData. unknown type: %s", typ)
	}
	return nil
}

func (p *PaymentRequestInfoData) unmarshalFromCollection(typ string, data []byte) error {
	switch typ {
	case Iden3PaymentRequestCryptoV1Type:
		if err := json.Unmarshal(data, &p.crypto); err != nil {
			return fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
	case Iden3PaymentRailsRequestV1Type:
		if err := json.Unmarshal(data, &p.rails); err != nil {
			return fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
	case Iden3PaymentRailsERC20RequestV1Type:
		if err := json.Unmarshal(data, &p.railsERC); err != nil {
			return fmt.Errorf("unmarshalling PaymentRequestInfoData: %w", err)
		}
	default:
		return errors.Errorf("unmarshalling PaymentRequestInfoData. unknown type: %s", typ)
	}
	return nil
}

// Iden3PaymentRequestCryptoV1 represents the Iden3PaymentRequestCryptoV1 payment request data.
type Iden3PaymentRequestCryptoV1 struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Context    string `json:"@context,omitempty"`
	ChainID    string `json:"chainId"`
	Address    string `json:"address"`
	Amount     string `json:"amount"`
	Currency   string `json:"currency"`
	Expiration string `json:"expiration,omitempty"`
}

// Iden3PaymentRailsRequestV1 represents the Iden3PaymentRailsRequestV1 payment request data.
type Iden3PaymentRailsRequestV1 struct {
	Nonce          string                         `json:"nonce"`
	Type           string                         `json:"type"`
	Context        PaymentContext                 `json:"@context"`
	Recipient      string                         `json:"recipient"`
	Amount         string                         `json:"amount"` // Not negative number
	ExpirationDate string                         `json:"expirationDate"`
	Proof          EthereumEip712Signature2021Col `json:"proof"`
	Metadata       string                         `json:"metadata"`
	Currency       string                         `json:"currency"`
}

// Iden3PaymentRailsERC20RequestV1 represents the Iden3PaymentRailsERC20RequestV1 payment request data.
type Iden3PaymentRailsERC20RequestV1 struct {
	Nonce          string                         `json:"nonce"`
	Type           string                         `json:"type"`
	Context        PaymentContext                 `json:"@context"`
	Recipient      string                         `json:"recipient"`
	Amount         string                         `json:"amount"` // Not negative number
	ExpirationDate string                         `json:"expirationDate"`
	Proof          EthereumEip712Signature2021Col `json:"proof"`
	Metadata       string                         `json:"metadata"`
	Currency       string                         `json:"currency"`
	TokenAddress   string                         `json:"tokenAddress"`
	Features       []PaymentFeatures              `json:"features,omitempty"`
}

// PaymentFeatures represents type Features used in ERC20 payment request.
type PaymentFeatures string

// EthereumEip712Signature2021Col is a list of EthereumEip712Signature2021.
type EthereumEip712Signature2021Col []EthereumEip712Signature2021

// UnmarshalJSON unmarshal the PaymentRequestInfoData from JSON.
func (p *EthereumEip712Signature2021Col) UnmarshalJSON(data []byte) error {
	var col []EthereumEip712Signature2021
	if err := json.Unmarshal(data, &col); err != nil {
		var single EthereumEip712Signature2021
		if err := json.Unmarshal(data, &single); err != nil {
			return fmt.Errorf("failed to unmarshal EthereumEip712Signature2021Col: %w", err)
		}
		col = append(col, single)
	}
	*p = col
	return nil
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

// PaymentRequestInfoCredentials represents the payment request credentials.
type PaymentRequestInfoCredentials struct {
	Context string `json:"context,omitempty"`
	Type    string `json:"type,omitempty"`
}

// PaymentMessage represents Iden3message for payment.
type PaymentMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body PaymentMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// PaymentMessageBody represents the body of the PaymentMessage.
type PaymentMessageBody struct {
	Payments []Payment `json:"payments"`
}

// Payment is a union type for field Payments in PaymentMessageBody.
// Only one of the fields can be set at a time.
type Payment struct {
	dataType string
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

// NEwPaymentRailsERC20 creates a new Payment with Iden3PaymentRailsERC20V1 data.
func NEwPaymentRailsERC20(data Iden3PaymentRailsERC20V1) Payment {
	return Payment{
		dataType: Iden3PaymentRailsERC20V1Type,
		railsERC: &data,
	}
}

// Type returns the type of the data in the union. You can use Data() to get the data.
func (p *Payment) Type() string {
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
	}
	return nil
}

// UnmarshalJSON unmarshal the Payment from JSON.
func (p *Payment) UnmarshalJSON(bytes []byte) error {
	var item struct {
		Type string `json:"type"`
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
	}
	return nil, errors.New("failed to marshal not initialized Payment")
}

// Iden3PaymentCryptoV1 represents the Iden3PaymentCryptoV1 payment data.
type Iden3PaymentCryptoV1 struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Context     PaymentContext `json:"@context,omitempty"`
	PaymentData struct {
		TxID string `json:"txId"`
	} `json:"paymentData"`
}

// Iden3PaymentRailsV1 represents the Iden3PaymentRailsV1 payment data.
type Iden3PaymentRailsV1 struct {
	Nonce       string         `json:"nonce"`
	Type        string         `json:"type"`
	Context     PaymentContext `json:"@context,omitempty"`
	PaymentData struct {
		TxID    string `json:"txId"`
		ChainID string `json:"chainId"`
	} `json:"paymentData"`
}

// Iden3PaymentRailsERC20V1 represents the Iden3PaymentRailsERC20V1 payment data.
type Iden3PaymentRailsERC20V1 struct {
	Nonce       string         `json:"nonce"`
	Type        string         `json:"type"`
	Context     PaymentContext `json:"@context,omitempty"`
	PaymentData struct {
		TxID         string `json:"txId"`
		ChainID      string `json:"chainId"`
		TokenAddress string `json:"tokenAddress"`
	} `json:"paymentData"`
}

// PaymentContext represents the payment context.
type PaymentContext struct {
	str     *string
	strCol  []string
	itemCol []interface{}
}

// NewPaymentContextString creates a new PaymentContext with a string.
func NewPaymentContextString(str string) PaymentContext {
	return PaymentContext{str: &str}
}

// NewPaymentContextStringCol creates a new PaymentContext with a string collection.
func NewPaymentContextStringCol(strCol []string) PaymentContext {
	return PaymentContext{strCol: strCol}
}

// NewPaymentContextItemCol creates a new PaymentContext with an interface{} collection.
func NewPaymentContextItemCol(itemCol []interface{}) PaymentContext {
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
