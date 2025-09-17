package mock

import (
	"crypto/ecdh"
	"crypto/rsa"
	"encoding/json"
	"io"
	"math/rand"
	"testing"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

const (
	rsaBits = 2048
)

var (
	AliceDigest  = rand.New(rand.NewSource(1))
	BobDigest    = rand.New(rand.NewSource(2))
	ViktorDigest = rand.New(rand.NewSource(3))
)

type MockRSA struct {
	PrivateKey *rsa.PrivateKey
}

type MockEC struct {
	PrivateKey *ecdh.PrivateKey
}

func NewMockRSA(t *testing.T, r io.Reader) MockRSA {
	p, err := rsa.GenerateKey(r, rsaBits)
	require.NoError(t, err)
	return MockRSA{PrivateKey: p}
}

func (m MockRSA) GetJWKForPrivateKey(t *testing.T) map[string]interface{} {
	jmap := ToJWK(t, m.PrivateKey)
	jmap["alg"] = jwa.RSA_OAEP_256().String()
	return jmap
}

func (m MockRSA) GetJWKForPublicKey(t *testing.T) map[string]interface{} {
	jmap := ToJWK(t, m.PrivateKey.Public())
	jmap["alg"] = jwa.RSA_OAEP_256().String()
	return jmap
}

func (m MockRSA) BuildDidDocWithRSAKey(t *testing.T, did string) *document.DidResolution {
	jwk := m.GetJWKForPublicKey(t)
	return &document.DidResolution{
		DidDocument: &verifiable.DIDDocument{
			ID: did,
			VerificationMethod: []verifiable.CommonVerificationMethod{
				{
					ID:           did + "#key-1",
					Type:         "JsonWebKey2020",
					Controller:   did,
					PublicKeyJwk: jwk,
				},
			},
		},
	}
}

func NewMockEC(t *testing.T, r io.Reader) MockEC {
	privKey, err := ecdh.P256().GenerateKey(r)
	require.NoError(t, err)
	return MockEC{PrivateKey: privKey}
}

func (m MockEC) GetJWKForPrivateKey(t *testing.T) map[string]interface{} {
	jmap := ToJWK(t, m.PrivateKey)
	jmap["alg"] = jwa.ECDH_ES_A256KW().String()
	return jmap
}

func (m MockEC) GetJWKForPublicKey(t *testing.T) map[string]interface{} {
	jmap := ToJWK(t, m.PrivateKey.PublicKey())
	jmap["alg"] = jwa.ECDH_ES_A256KW().String()
	return jmap
}

func (m MockEC) BuildDidDocWithECKey(t *testing.T, did string) *document.DidResolution {
	jwk := m.GetJWKForPublicKey(t)
	return &document.DidResolution{
		DidDocument: &verifiable.DIDDocument{
			ID: did,
			VerificationMethod: []verifiable.CommonVerificationMethod{
				{
					ID:           did + "#key-1",
					Type:         "JsonWebKey2020",
					Controller:   did,
					PublicKeyJwk: jwk,
				},
			},
		},
	}
}

func ToJWK(t *testing.T, key any) map[string]interface{} {
	k, err := jwk.Import(key)
	require.NoError(t, err)

	kbytes, err := json.Marshal(k)
	require.NoError(t, err)

	var kmap map[string]interface{}
	err = json.Unmarshal(kbytes, &kmap)
	require.NoError(t, err)

	return kmap
}
