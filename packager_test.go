package iden3comm_test

import (
	"context"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/iden3/go-circuits"
	circuitsTesting "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/iden3comm"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/iden3/jwz"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func MockPrepareAuthInputs(hash []byte, id *core.ID, circuitID circuits.CircuitID) (circuits.AuthInputs, error) {
	challenge := new(big.Int).SetBytes(hash)

	ctx := context.Background()
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	identifier, claim, state, claimsTree, revTree, rootsTree, claimEntryMTP, claimNonRevMTP, signature, err := circuitsTesting.AuthClaimFullInfo(ctx, privKeyHex, challenge)
	if err != nil {
		return circuits.AuthInputs{}, err
	}
	treeState := circuits.TreeState{
		State:          state,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	inputs := circuits.AuthInputs{
		ID: identifier,
		AuthClaim: circuits.Claim{
			Claim:       claim,
			Proof:       claimEntryMTP,
			TreeState:   treeState,
			NonRevProof: circuits.ClaimNonRevStatus{TreeState: treeState, Proof: claimNonRevMTP},
		},
		Signature: signature,
		Challenge: challenge,
	}
	return inputs, nil
}

func TestPackagerPlainPacker(t *testing.T) {
	pm := iden3comm.NewPackageManager()
	pm.RegisterPackers(&packers.PlainMessagePacker{})

	identifier := "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ"

	senderID, err := core.IDFromString(identifier)
	assert.NoError(t, err)
	var msg protocol.CredentialFetchRequestMessage
	msg.From = identifier
	msg.To = identifier

	claimID, err := uuid.NewV4()
	assert.NoError(t, err)

	msg.Type = protocol.CredentialFetchRequestMessageType
	msg.Body = protocol.CredentialFetchRequestMessageBody{
		ClaimID: claimID.String(),
		Schema: protocol.Schema{
			URL:  "http://schema.url",
			Type: "KYCAgeCredential",
		},
	}
	marshalledMsg, err := json.Marshal(msg)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypePlainMessage, marshalledMsg, &senderID)
	assert.NoError(t, err)

	t.Log(string(envelope))

	unpackedMsg, err := pm.Unpack(envelope)
	assert.NoError(t, err)

	switch unpackedMsg.Type {
	case protocol.CredentialFetchRequestMessageType:
		var fetchRequestBody protocol.CredentialFetchRequestMessageBody
		err = json.Unmarshal(unpackedMsg.Body, &fetchRequestBody)
		assert.NoError(t, err)
		assert.Equal(t, msg.Body.ClaimID, fetchRequestBody.ClaimID)
		assert.ObjectsAreEqual(msg.Body.Schema, fetchRequestBody.Schema)
	default:
		assert.FailNow(t, "message type %s is not supported by agent", unpackedMsg.Type)
	}

}

func TestPackagerZKPPacker(t *testing.T) {
	pm := iden3comm.NewPackageManager()
	pm.RegisterPackers(&packers.PlainMessagePacker{})
	pm.RegisterPackers(packers.NewZKPPacker(jwz.ProvingMethodGroth16AuthInstance, func(hash []byte, id *core.ID, circuitID circuits.CircuitID) (circuits.InputsMarshaller, error) {
		return MockPrepareAuthInputs(hash, id, circuitID)
	}))

	identifier := "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ"

	senderID, err := core.IDFromString(identifier)
	assert.NoError(t, err)
	var msg protocol.CredentialFetchRequestMessage
	msg.From = identifier
	msg.To = identifier

	claimID, err := uuid.NewV4()
	assert.NoError(t, err)

	msg.Type = protocol.CredentialFetchRequestMessageType
	msg.Body = protocol.CredentialFetchRequestMessageBody{
		ClaimID: claimID.String(),
		Schema: protocol.Schema{
			URL:  "http://schema.url",
			Type: "KYCAgeCredential",
		},
	}
	marshalledMsg, err := json.Marshal(msg)
	assert.NoError(t, err)

	envelope, err := pm.Pack(packers.MediaTypeZKPMessage, marshalledMsg, &senderID)
	assert.NoError(t, err)

	t.Log(string(envelope))

	unpackedMsg, err := pm.Unpack(envelope)
	assert.NoError(t, err)

	switch unpackedMsg.Type {
	case protocol.CredentialFetchRequestMessageType:
		var fetchRequestBody protocol.CredentialFetchRequestMessageBody
		err = json.Unmarshal(unpackedMsg.Body, &fetchRequestBody)

		assert.NoError(t, err)
		assert.Equal(t, msg.Body.ClaimID, fetchRequestBody.ClaimID)
		assert.ObjectsAreEqual(msg.Body.Schema, fetchRequestBody.Schema)

	default:
		assert.FailNow(t, "message type %s is not supported by agent", unpackedMsg.Type)
	}

}
