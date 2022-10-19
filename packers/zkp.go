package packers

import (
	"encoding/json"
	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-jwz"
	"github.com/iden3/iden3comm"
	"github.com/pkg/errors"
	"math/big"
)

// MediaTypeZKPMessage is media type for jwz
const MediaTypeZKPMessage iden3comm.MediaType = "application/iden3-zkp-json"

// AuthDataPreparerHandlerFunc registers the handler function for inputs preparation.
type AuthDataPreparerHandlerFunc func(hash []byte, id *core.ID, circuitID circuits.CircuitID) ([]byte, error)

// Prepare function is responsible to call provided handler for inputs preparation
func (f AuthDataPreparerHandlerFunc) Prepare(hash []byte, id *core.ID, circuitID circuits.CircuitID) ([]byte, error) {
	return f(hash, id, circuitID)
}

// StateVerificationHandlerFunc  registers the handler function for state verification.
type StateVerificationHandlerFunc func(id circuits.CircuitID, pubsignals []string) error

// Verify function is responsible to call provided handler for outputs verification
func (f StateVerificationHandlerFunc) Verify(id circuits.CircuitID, pubsignals []string) error {
	return f(id, pubsignals)
}

// StateVerificationFunc must verify pubsignals for circuit id
type StateVerificationFunc func(id circuits.CircuitID, pubsignals []string) error

// ZKPPacker is  packer that use JWZ
type ZKPPacker struct {
	ProvingMethod    jwz.ProvingMethod
	VerificationKeys map[circuits.CircuitID][]byte
	ProvingKey       []byte
	Wasm             []byte
	AuthDataPreparer AuthDataPreparerHandlerFunc
	StateVerifier    StateVerificationHandlerFunc
}

// ZKPPackerParams is params for zkp packer
type ZKPPackerParams struct {
	SenderID *core.ID
	iden3comm.PackerParams
}

// NewZKPPacker creates new instance of zkp Packer.
// Pack works only with a specific proving Method
// Unpack is universal function that supports all proving method defined in jwz.
func NewZKPPacker(provingMethod jwz.ProvingMethod, authDataPreparer AuthDataPreparerHandlerFunc,
	stateVerifier StateVerificationHandlerFunc,
	provingKey, wasm []byte,
	keys map[circuits.CircuitID][]byte) *ZKPPacker {

	return &ZKPPacker{
		ProvingMethod:    provingMethod,
		AuthDataPreparer: authDataPreparer,
		VerificationKeys: keys,
		ProvingKey:       provingKey,
		Wasm:             wasm,
		StateVerifier:    stateVerifier,
	}
}

// Pack returns packed message to transport envelope with a zero knowledge proof in JWZ full serialized format
func (p *ZKPPacker) Pack(payload []byte, params iden3comm.PackerParams) ([]byte, error) {

	// create hash of message
	var err error
	var token *jwz.Token

	zkpParams, ok := params.(ZKPPackerParams)
	if !ok {
		return nil, errors.New("can't cast params to zkp packer params")
	}

	token, err = jwz.NewWithPayload(p.ProvingMethod, payload, func(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
		return p.AuthDataPreparer.Prepare(hash, zkpParams.SenderID, circuitID)
	})
	if err != nil {
		return nil, err
	}

	err = token.WithHeader(jwz.HeaderType, MediaTypeZKPMessage)
	if err != nil {
		return nil, err
	}

	tokenStr, err := token.Prove(p.ProvingKey, p.Wasm)
	if err != nil {
		return nil, err
	}

	return []byte(tokenStr), nil
}

// Unpack returns unpacked message from transport envelope with verification of zeroknowledge proof
func (p *ZKPPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {

	token, err := jwz.Parse(string(envelope))
	if err != nil {
		return nil, err
	}

	verificationKey, ok := p.VerificationKeys[circuits.CircuitID(token.CircuitID)]
	if !ok {
		return nil, errors.New("message was packed with unsupported circuit")
	}

	isValid, err := token.Verify(verificationKey)
	if err != nil {
		return nil, err
	}
	if !isValid {
		return nil, errors.New("message proof is invalid")
	}

	err = p.StateVerifier.Verify(circuits.CircuitID(token.CircuitID), token.ZkProof.PubSignals)
	if err != nil {
		return nil, err
	}

	var msg iden3comm.BasicMessage
	err = json.Unmarshal(token.GetPayload(), &msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// check that sender of the message is presented in proof
	err = verifySender(token, msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &msg, err
}
func verifySender(token *jwz.Token, msg iden3comm.BasicMessage) error {

	bytePubsig, err := json.Marshal(token.ZkProof.PubSignals)
	if err != nil {
		return err
	}

	var userID *big.Int

	switch circuits.CircuitID(token.CircuitID) {
	case circuits.AuthCircuitID:
		authPubSignals := circuits.AuthPubSignals{}
		err = authPubSignals.PubSignalsUnmarshal(bytePubsig)
		if err != nil {
			return err
		}
		userID = authPubSignals.UserID.BigInt()
	default:
		return errors.Errorf("'%s' unknow circuit ID. can't verify msg sender", token.CircuitID)
	}
	id, err := core.IDFromInt(userID)
	if err != nil {
		return err
	}

	if msg.From != id.String() {
		return errors.Errorf("sender of message is not used for jwz token creation, expected: '%s' got: '%s", msg.From, userID.String())
	}

	return nil
}

// MediaType for iden3comm that returns MediaTypeZKPMessage
func (p *ZKPPacker) MediaType() iden3comm.MediaType {
	return MediaTypeZKPMessage
}
