package iden3comm_test

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-jwz"
	"github.com/iden3/iden3comm"
	"github.com/iden3/iden3comm/mock"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackagerPlainPacker(t *testing.T) {
	pm := iden3comm.NewPackageManager()
	err := pm.RegisterPackers(&packers.PlainMessagePacker{})
	assert.NoError(t, err)

	identifier := "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"

	senderDID, err := core.ParseDID(identifier)
	assert.NoError(t, err)

	targetIdentifier := "did:iden3:polygon:mumbai:wzWeGdtjvKtUP1oTxQP5t5iZGDX3HNfEU5xR8MZAt"

	targetID, err := core.ParseDID(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypePlainMessage, senderDID, targetID)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypePlainMessage, marshalledMsg, packers.PlainPackerParams{})
	assert.NoError(t, err)

	unpackedMsg, unpackerType, err := pm.Unpack(envelope)
	assert.NoError(t, err)
	assert.Equal(t, packers.MediaTypePlainMessage, unpackerType)
	assert.Equal(t, unpackedMsg.Typ, unpackerType)

	switch unpackedMsg.Type {
	case protocol.CredentialFetchRequestMessageType:
		var fetchRequestBody protocol.CredentialFetchRequestMessageBody
		err = json.Unmarshal(unpackedMsg.Body, &fetchRequestBody)
		assert.NoError(t, err)
		assert.NotEmpty(t, fetchRequestBody)
	default:
		assert.FailNow(t, "message type %s is not supported by agent", unpackedMsg.Type)
	}

}

func TestPackagerZKPPacker(t *testing.T) {
	pm := initPackageManager(t)

	identifier := "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"

	senderDID, err := core.ParseDID(identifier)
	assert.NoError(t, err)

	targetIdentifier := "did:iden3:polygon:mumbai:wzWeGdtjvKtUP1oTxQP5t5iZGDX3HNfEU5xR8MZAt"

	targetID, err := core.ParseDID(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypeZKPMessage, senderDID, targetID)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypeZKPMessage, marshalledMsg, packers.ZKPPackerParams{SenderID: senderDID,
		ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "authV2"}})
	assert.NoError(t, err)

	unpackedMsg, unpackerType, err := pm.Unpack(envelope)
	assert.NoError(t, err)
	assert.Equal(t, packers.MediaTypeZKPMessage, unpackerType)
	assert.Equal(t, senderDID.String(), unpackedMsg.From)

}

func TestPackagerAnonryptPacker(t *testing.T) {

	pm := iden3comm.NewPackageManager()
	pm.RegisterPackers(packers.NewAnoncryptPacker(mock.ResolveEncPrivateKey), &packers.PlainMessagePacker{})
	// nolint :

	identifier := "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"

	senderDID, err := core.ParseDID(identifier)
	assert.NoError(t, err)

	targetIdentifier := "did:iden3:polygon:mumbai:wzWeGdtjvKtUP1oTxQP5t5iZGDX3HNfEU5xR8MZAt"

	targetID, err := core.ParseDID(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypeEncryptedMessage, senderDID, targetID)
	assert.NoError(t, err)

	key, err := mock.ResolveKeyID(mock.MockRecipientKeyID)
	require.NoError(t, err)
	envelope, err := pm.Pack(packers.MediaTypeEncryptedMessage, marshalledMsg, packers.AnoncryptPackerParams{RecipientKey: &key})
	assert.NoError(t, err)

	unpackedMsg, unpackerType, err := pm.Unpack(envelope)
	assert.NoError(t, err)
	assert.Equal(t, unpackedMsg.Typ, unpackerType)

	actualMSGBytes, err := json.Marshal(unpackedMsg)
	assert.NoError(t, err)

	assert.JSONEq(t, string(marshalledMsg), string(actualMSGBytes))

}

// check that MediaTypeZKPMessage will take only from jwz header, not from body.
func TestPackagerZKPPacker_OtherMessageTypeInBody(t *testing.T) {

	pm := initPackageManager(t)

	identifier := "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"

	senderDID, err := core.ParseDID(identifier)
	assert.NoError(t, err)

	targetIdentifier := "did:iden3:polygon:mumbai:wzWeGdtjvKtUP1oTxQP5t5iZGDX3HNfEU5xR8MZAt"

	targetID, err := core.ParseDID(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypePlainMessage, senderDID, targetID)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypeZKPMessage, marshalledMsg, packers.ZKPPackerParams{
		SenderID:         senderDID,
		ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "authV2"},
	})
	assert.NoError(t, err)

	unpackedMsg, unpackerType, err := pm.Unpack(envelope)
	assert.NoError(t, err)
	assert.Equal(t, packers.MediaTypeZKPMessage, unpackerType)

	// check that type of unpacker was taken from jwz header, not body.
	assert.NotEqual(t, unpackedMsg.Typ, unpackerType)
}

func TestUnpackWithType(t *testing.T) {

	pm := initPackageManager(t)

	identifier := "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"

	senderDID, err := core.ParseDID(identifier)
	assert.NoError(t, err)

	var msg protocol.CredentialFetchRequestMessage
	msg.From = identifier
	msg.To = identifier

	claimID, err := uuid.NewV4()
	assert.NoError(t, err)

	msg.Type = protocol.CredentialFetchRequestMessageType
	msg.Typ = packers.MediaTypeZKPMessage
	msg.Body = protocol.CredentialFetchRequestMessageBody{
		ID: claimID.String(),
	}
	marshalledMsg, err := json.Marshal(msg)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypeZKPMessage, marshalledMsg, packers.ZKPPackerParams{
		SenderID:         senderDID,
		ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "authV2"},
	})
	assert.NoError(t, err)

	unpackedMsg, err := pm.UnpackWithType(packers.MediaTypeZKPMessage, envelope)
	assert.NoError(t, err)
	assert.Equal(t, unpackedMsg.Typ, packers.MediaTypeZKPMessage)
}

func createFetchCredentialMessage(typ iden3comm.MediaType, from, to *core.DID) ([]byte, error) {

	var msg protocol.CredentialFetchRequestMessage
	msg.From = from.String()
	msg.To = to.String()
	msg.Typ = typ
	claimID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	msg.Type = protocol.CredentialFetchRequestMessageType
	msg.Body = protocol.CredentialFetchRequestMessageBody{
		ID: claimID.String(),
	}
	marshalledMsg, err := json.Marshal(msg)
	return marshalledMsg, err
}

func initPackageManager(t *testing.T) *iden3comm.PackageManager {
	pm := iden3comm.NewPackageManager()
	err := pm.RegisterPackers(&packers.PlainMessagePacker{})
	require.NoError(t, err)
	mockedProvingMethod := &mock.ProvingMethodGroth16AuthV2{ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "authV2"}}

	jwz.RegisterProvingMethod(mockedProvingMethod.ProvingMethodAlg, func() jwz.ProvingMethod {
		return mockedProvingMethod
	})

	mockVerificationParam := make(map[jwz.ProvingMethodAlg]packers.VerificationParams)
	mockVerificationParam[mockedProvingMethod.ProvingMethodAlg] = packers.NewVerificationParams([]byte(""), mock.VerifyState)

	mockProvingParamMap := make(map[jwz.ProvingMethodAlg]packers.ProvingParams)
	mockProvingParamMap[mockedProvingMethod.ProvingMethodAlg] = packers.NewProvingParams(mock.PrepareAuthInputs, []byte{}, []byte{})

	err = pm.RegisterPackers(packers.NewZKPPacker(mockProvingParamMap, mockVerificationParam))
	require.NoError(t, err)

	return pm
}
