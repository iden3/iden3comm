package mock

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/iden3/go-circuits"
	circuitsTesting "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-jwz"
	"github.com/iden3/go-rapidsnark/types"
	"gopkg.in/square/go-jose.v2"
)

// ProvingMethodGroth16Auth proving method to avoid using of proving key and wasm files
type ProvingMethodGroth16Auth struct {
	jwz.ProvingMethodAlg
}

// Alg returns current zk alg
func (m *ProvingMethodGroth16Auth) Alg() string {
	return m.ProvingMethodAlg.Alg
}

// CircuitID returns name of circuit
func (m *ProvingMethodGroth16Auth) CircuitID() string {
	return m.ProvingMethodAlg.CircuitID
}

// Verify return no error for any proof
func (m *ProvingMethodGroth16Auth) Verify(messageHash []byte, proof *types.ZKProof, verificationKey []byte) error {
	return nil
}

// Prove generates proof using auth circuit and groth16 alg, checks that proven message hash is set as a part of circuit specific inputs
func (m *ProvingMethodGroth16Auth) Prove(inputs, provingKey, wasm []byte) (*types.ZKProof, error) {

	return &types.ZKProof{
		Proof: &types.ProofData{
			A:        nil,
			B:        nil,
			C:        nil,
			Protocol: "groth16",
		},
		PubSignals: []string{"179949150130214723420589610911161895495647789006649785264738141299135414272", "1", "379949150130214723420589610911161895495647789006649785264738141299135414272"},
	}, nil
}

// PrepareAuthInputs returns mocked inputs for auth circuit
func PrepareAuthInputs(hash []byte, id *core.ID, circuitID circuits.CircuitID) ([]byte, error) {
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
		AuthClaim: circuits.Claim{
			Claim:       claim,
			Proof:       claimEntryMTP,
			TreeState:   treeState,
			NonRevProof: &circuits.ClaimNonRevStatus{TreeState: treeState, Proof: claimNonRevMTP},
		},
		Signature: signature,
		Challenge: challenge,
	}

	return inputs.InputsMarshal()
}

// VerifyState return no error always
func VerifyState(id circuits.CircuitID, signals []string) error {
	return nil
}

// MockRecipientKeyID is mocked key id for recipient
const MockRecipientKeyID = "123456789"

// ResolveKeyID returns mocked public key for any key ID
func ResolveKeyID(keyID string) (jose.JSONWebKey, error) {
	recipientPrivKey, _ := ResolveEncPrivateKey(keyID)
	recipientPubKey := jose.JSONWebKey{
		Key:       &recipientPrivKey.(*ecdsa.PrivateKey).PublicKey,
		KeyID:     keyID,
		Algorithm: "PS256",
		Use:       "enc",
	}
	return recipientPubKey, nil
}

// ResolveEncPrivateKey returns mocked private key
func ResolveEncPrivateKey(keyID string) (interface{}, error) {
	seed := new(big.Int)
	// key id should be integer
	seed.SetString(keyID, 16)

	recipientPrivKey := new(ecdsa.PrivateKey)
	recipientPrivKey.PublicKey.Curve = elliptic.P256()
	recipientPrivKey.D = seed
	recipientPrivKey.PublicKey.X, recipientPrivKey.PublicKey.Y = recipientPrivKey.PublicKey.Curve.ScalarBaseMult(seed.Bytes())
	return recipientPrivKey, nil
}
