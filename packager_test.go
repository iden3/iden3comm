package iden3comm_test

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/iden3/go-circuits"
	circuitsTesting "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-jwz"
	"github.com/iden3/iden3comm"
	"github.com/iden3/iden3comm/mock"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func MockPrepareAuthInputs(hash []byte, id *core.ID, circuitID circuits.CircuitID) ([]byte, error) {
	challenge := new(big.Int).SetBytes(hash)

	ctx := context.Background()
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	identifier, claim, state, claimsTree, revTree, rootsTree, claimEntryMTP, claimNonRevMTP, signature, err := circuitsTesting.AuthClaimFullInfo(ctx, privKeyHex, challenge)
	if err != nil {
		return nil, err
	}
	treeState := circuits.TreeState{
		State:          state,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	inputs := circuits.AuthInputs{
		ID: identifier,
		AuthClaim: circuits.ClaimWithMTPProof{
			Claim: claim,
			IncProof: circuits.MTProof{
				Proof:     claimEntryMTP,
				TreeState: treeState,
			},
			NonRevProof: circuits.MTProof{
				TreeState: treeState,
				Proof:     claimNonRevMTP,
			},
		},
		Signature: signature,
		Challenge: challenge,
	}
	return inputs.InputsMarshal()
}

func TestPackagerPlainPacker(t *testing.T) {
	pm := iden3comm.NewPackageManager()
	pm.RegisterPackers(&packers.PlainMessagePacker{})

	identifier := "x3RYZ1C3re8qSKwhQwDL3PHN5jvMizbQYsGFM1DCY"

	senderID, err := core.IDFromString(identifier)
	assert.NoError(t, err)

	targetIdentifier := "ww1LNXF9vfzD5gsUuh97VecoEsj7qss2X9dKN99YN"

	targetID, err := core.IDFromString(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypePlainMessage, &senderID, &targetID)
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

	identifier := "x3RYZ1C3re8qSKwhQwDL3PHN5jvMizbQYsGFM1DCY"

	senderID, err := core.IDFromString(identifier)
	assert.NoError(t, err)

	targetIdentifier := "ww1LNXF9vfzD5gsUuh97VecoEsj7qss2X9dKN99YN"

	targetID, err := core.IDFromString(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypeZKPMessage, &senderID, &targetID)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypeZKPMessage, marshalledMsg, packers.ZKPPackerParams{SenderID: &senderID,
		ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "auth"}})
	assert.NoError(t, err)

	unpackedMsg, unpackerType, err := pm.Unpack(envelope)
	assert.NoError(t, err)
	assert.Equal(t, packers.MediaTypeZKPMessage, unpackerType)
	assert.Equal(t, senderID.String(), unpackedMsg.From)

}

func TestPackagerAnonryptPacker(t *testing.T) {
	pm := iden3comm.NewPackageManager()
	pm.RegisterPackers(packers.NewAnoncryptPacker(mock.ResolveEncPrivateKey), &packers.PlainMessagePacker{})
	// nolint :

	identifier := "x3RYZ1C3re8qSKwhQwDL3PHN5jvMizbQYsGFM1DCY"

	id, err := core.IDFromString(identifier)
	assert.NoError(t, err)

	targetIdentifier := "ww1LNXF9vfzD5gsUuh97VecoEsj7qss2X9dKN99YN"

	targetID, err := core.IDFromString(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypeEncryptedMessage, &id, &targetID)
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

	identifier := "ww1LNXF9vfzD5gsUuh97VecoEsj7qss2X9dKN99YN"

	senderID, err := core.IDFromString(identifier)
	assert.NoError(t, err)

	targetIdentifier := "x3RYZ1C3re8qSKwhQwDL3PHN5jvMizbQYsGFM1DCY"

	targetID, err := core.IDFromString(targetIdentifier)
	assert.NoError(t, err)

	marshalledMsg, err := createFetchCredentialMessage(packers.MediaTypePlainMessage, &senderID, &targetID)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypeZKPMessage, marshalledMsg, packers.ZKPPackerParams{
		SenderID:         &senderID,
		ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "auth"},
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

	identifier := "x3RYZ1C3re8qSKwhQwDL3PHN5jvMizbQYsGFM1DCY"

	senderID, err := core.IDFromString(identifier)
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
		SenderID:         &senderID,
		ProvingMethodAlg: jwz.ProvingMethodAlg{Alg: "groth16-mock", CircuitID: "auth"},
	})
	assert.NoError(t, err)

	unpackedMsg, err := pm.UnpackWithType(packers.MediaTypeZKPMessage, envelope)
	assert.NoError(t, err)
	assert.Equal(t, unpackedMsg.Typ, packers.MediaTypeZKPMessage)
}

func createFetchCredentialMessage(typ iden3comm.MediaType, from, to *core.ID) ([]byte, error) {

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
	pm.RegisterPackers(&packers.PlainMessagePacker{})

	mockedProvingMethod := &mock.ProvingMethodGroth16Auth{
		ProvingMethodAlg: jwz.ProvingMethodAlg{
			Alg:       "groth16-mock",
			CircuitID: "auth",
		},
	}

	jwz.RegisterProvingMethod(mockedProvingMethod.ProvingMethodAlg, func() jwz.ProvingMethod {
		return mockedProvingMethod
	})
	// vk := packers.NewVerificationKey(circuits.CircuitID(mockedProvingMethod.ProvingMethodAlg.CircuitID),
	//	mockedProvingMethod.Alg())

	mockVerificationParam := make(map[jwz.ProvingMethodAlg]packers.VerificationParam)
	mockVerificationParam[mockedProvingMethod.ProvingMethodAlg] = packers.NewVerificationParam([]byte(""), mock.VerifyState)

	mockProvingParamMap := make(map[jwz.ProvingMethodAlg]packers.ProvingParam)
	mockProvingParamMap[mockedProvingMethod.ProvingMethodAlg] = packers.NewProvingParam(mock.PrepareAuthInputs, []byte{}, []byte{})

	err := pm.RegisterPackers(packers.NewZKPPacker(mockProvingParamMap, mockVerificationParam))
	assert.NoError(t, err)

	return pm
}
