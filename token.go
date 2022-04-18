package iden3comm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits"
	"gopkg.in/square/go-jose.v2"
)

// JSONWebZeroknowledge is json web token with signature presented by zero knowledge proof
type JSONWebZeroknowledge struct {
	Payload []byte `json:"payload"`
	Header  []byte `json:"header"`
	ZKP     []byte `json:"zkp"`
}

// SetHeader set headers for jwz
func (token *JSONWebZeroknowledge) SetHeader(zkpAlg string, id circuits.CircuitID, typ string) error {
	joseHeaders := map[string]string{
		"alg":       zkpAlg,
		"crit":      "circuitId",
		"circuitId": string(id),
		"typ":       typ,
	}

	joseHeadersBytes, err := json.Marshal(joseHeaders)
	if err != nil {
		return err
	}
	token.Header = joseHeadersBytes
	return nil
}

// FullSerialize returns a serialized data
func (token *JSONWebZeroknowledge) FullSerialize() ([]byte, error) {
	joseJWS, err := jose.ParseSigned(token.ToString())
	if err != nil {
		return nil, err
	}
	fullSerialized := joseJWS.FullSerialize()
	return []byte(fullSerialized), nil
}

// ToString  Returns string representation of JWZ token
func (token *JSONWebZeroknowledge) ToString() string {
	header := base64.RawURLEncoding.EncodeToString(token.Header)
	payload := base64.RawURLEncoding.EncodeToString(token.Payload)
	proof := base64.RawURLEncoding.EncodeToString(token.ZKP)

	return fmt.Sprintf("%s.%s.%s", header, payload, proof)
}
