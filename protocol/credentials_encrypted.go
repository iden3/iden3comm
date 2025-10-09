// # Experimental
// Notice: this functionality is in beta and can be deleted or be non-backward compatible in the future releases.

package protocol

import (
	"encoding/json"

	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/pkg/errors"
)

// EncryptedPayloadFormat represents format of encrypted credential payload
type EncryptedPayloadFormat string

const (
	// EncryptedFormatJWEJSONSerialization represents JWE JSON serialization format
	EncryptedFormatJWEJSONSerialization EncryptedPayloadFormat = "typ/jwe+json"
	// EncryptedFormatJWEStringSerialization represents JWE string serialization format
	EncryptedFormatJWEStringSerialization EncryptedPayloadFormat = "typ/jwe"
)

// EncryptedCredential represents an interface for handling encrypted credentials
type EncryptedCredential interface {
	Get(dst interface{}) error
	Type() EncryptedPayloadFormat
}

// EncryptedCredentialJWEJSONSerialization represents encrypted credential in JWE JSON serialization format
type EncryptedCredentialJWEJSONSerialization struct {
	json.RawMessage
}

// Get unmarshals the JSON encrypted credential into the provided destination
func (j *EncryptedCredentialJWEJSONSerialization) Get(dst interface{}) error {
	return json.Unmarshal(j.RawMessage, dst)
}

// Type returns the format type of the encrypted credential
func (j *EncryptedCredentialJWEJSONSerialization) Type() EncryptedPayloadFormat {
	return EncryptedFormatJWEJSONSerialization
}

// EncryptedCredentialJWEStringSerialization represents encrypted credential in JWE string serialization format
type EncryptedCredentialJWEStringSerialization string

// Get assigns the string encrypted credential to the provided destination
func (s *EncryptedCredentialJWEStringSerialization) Get(dst interface{}) error {
	strPtr, ok := dst.(*string)
	if !ok {
		return errors.New("dst must be of type *string")
	}
	*strPtr = string(*s)
	return nil
}

// Type returns the format type of the encrypted credential
func (s *EncryptedCredentialJWEStringSerialization) Type() EncryptedPayloadFormat {
	return EncryptedFormatJWEStringSerialization
}

// EncryptedCredentialIssuanceMessage represent Iden3message for encrypted credential issuance
type EncryptedCredentialIssuanceMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body EncryptedIssuanceMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`

	Attachments []iden3comm.Attachment `json:"attachments,omitempty"`
}

// EncryptedIssuanceMessageBody is struct the represents message when credential is issued and encrypted
type EncryptedIssuanceMessageBody struct {
	Credential struct {
		Payload EncryptedCredential `json:"payload"`
		verifiable.W3CCredential
	} `json:"credential"`
}

// UnmarshalJSON custom unmarshaller to handle different formats of encrypted credential
func (e *EncryptedIssuanceMessageBody) UnmarshalJSON(data []byte) error {
	str := struct {
		Credential struct {
			Payload json.RawMessage `json:"payload"`
			verifiable.W3CCredential
		} `json:"credential"`
	}{}

	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	e.Credential.W3CCredential = str.Credential.W3CCredential

	if len(str.Credential.Payload) == 0 {
		return errors.New("missing encrypted credential payload")
	}

	firstToken := str.Credential.Payload[0]
	switch firstToken {
	case '{':
		var jsonEnc EncryptedCredentialJWEJSONSerialization
		err = json.Unmarshal([]byte(str.Credential.Payload), &jsonEnc)
		if err != nil {
			return err
		}
		e.Credential.Payload = &jsonEnc
	case '"':
		var strEnc EncryptedCredentialJWEStringSerialization
		err = json.Unmarshal([]byte(str.Credential.Payload), &strEnc)
		if err != nil {
			return err
		}
		e.Credential.Payload = &strEnc
	default:
		return errors.New("unknown encrypted credential format")
	}

	return nil
}
