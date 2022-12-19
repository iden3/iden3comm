package packers

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-jwz"
	"github.com/iden3/iden3comm"
	"github.com/pkg/errors"
)

// MediaTypeZKPMessage is media type for jwz
const MediaTypeZKPMessage iden3comm.MediaType = "application/iden3-zkp-json"

// DataPreparerHandlerFunc registers the handler function for inputs preparation.
type DataPreparerHandlerFunc func(hash []byte, id *core.ID, circuitID circuits.CircuitID) ([]byte, error)

// Prepare function is responsible to call provided handler for inputs preparation
func (f DataPreparerHandlerFunc) Prepare(hash []byte, id *core.ID, circuitID circuits.CircuitID) ([]byte, error) {
	return f(hash, id, circuitID)
}

// VerificationHandlerFunc  registers the handler function for state verification.
type VerificationHandlerFunc func(id circuits.CircuitID, pubsignals []string) error

// Verify function is responsible to call provided handler for outputs verification
func (f VerificationHandlerFunc) Verify(id circuits.CircuitID, pubsignals []string) error {
	return f(id, pubsignals)
}

// StateVerificationFunc must verify pubsignals for circuit id
type StateVerificationFunc func(id circuits.CircuitID, pubsignals []string) error

// VerificationParam defined the verification function and the verification key for ZKP full verification
type VerificationParam struct {
	Key            []byte
	VerificationFn VerificationHandlerFunc
}

// NewVerificationParam create new params for verification handler.
func NewVerificationParam(key []byte, verifier VerificationHandlerFunc) VerificationParam {
	return VerificationParam{
		Key:            key,
		VerificationFn: verifier,
	}
}

// ZKPPacker is  packer that use JWZ
type ZKPPacker struct {
	Prover       map[jwz.ProvingMethodAlg]ProvingParam
	Verification map[jwz.ProvingMethodAlg]VerificationParam
}

// ProvingParam packer parameters for ZKP generation
type ProvingParam struct {
	DataPreparer DataPreparerHandlerFunc
	ProvingKey   []byte
	Wasm         []byte
}

// NewProvingParam defines the ZK proving parameters for ZKP generation
func NewProvingParam(dataPreparer DataPreparerHandlerFunc, provingKey, wasm []byte) ProvingParam {
	return ProvingParam{
		DataPreparer: dataPreparer,
		ProvingKey:   provingKey,
		Wasm:         wasm,
	}
}

// ZKPPackerParams is params for zkp packer
type ZKPPackerParams struct {
	SenderID         *core.ID
	ProvingMethodAlg jwz.ProvingMethodAlg
	iden3comm.PackerParams
}

// NewZKPPacker create new zkp packer.
func NewZKPPacker(provingParams map[jwz.ProvingMethodAlg]ProvingParam,
	verification map[jwz.ProvingMethodAlg]VerificationParam) *ZKPPacker {
	return &ZKPPacker{
		Prover:       provingParams,
		Verification: verification,
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

	if strings.Trim(zkpParams.ProvingMethodAlg.Alg, " ") == "" {
		return nil, errors.New("proving method alg is nil")
	}

	if strings.Trim(zkpParams.ProvingMethodAlg.CircuitID, " ") == "" {
		return nil, errors.New("proving method CircuitID is nil")
	}

	method := jwz.GetProvingMethod(zkpParams.ProvingMethodAlg)

	token, err = jwz.NewWithPayload(method, payload, func(hash []byte,
		circuitID circuits.CircuitID) ([]byte, error) {
		return p.Prover[zkpParams.ProvingMethodAlg].DataPreparer.Prepare(hash, zkpParams.SenderID, circuitID)
	})
	if err != nil {
		return nil, err
	}

	err = token.WithHeader(jwz.HeaderType, MediaTypeZKPMessage)
	if err != nil {
		return nil, err
	}

	tokenStr, err := token.Prove(p.Prover[zkpParams.ProvingMethodAlg].ProvingKey, p.Prover[zkpParams.ProvingMethodAlg].Wasm)
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

	verificationKey, ok := p.Verification[jwz.ProvingMethodAlg{Alg: token.Alg, CircuitID: token.CircuitID}]
	if !ok {
		return nil, fmt.Errorf("message was packed with unsupported circuit `%s` and alg `%s`", token.CircuitID, token.Alg)
	}

	isValid, err := token.Verify(verificationKey.Key)
	if err != nil {
		return nil, err
	}
	if !isValid {
		return nil, errors.New("message proof is invalid")
	}

	err = verificationKey.VerificationFn.Verify(circuits.CircuitID(token.CircuitID), token.ZkProof.PubSignals)
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

	switch circuits.CircuitID(token.CircuitID) {
	case circuits.AuthCircuitID:
		//nolint:gosec // fixed on main branch
		verifyAuthSender(msg.From, token.ZkProof.PubSignals)
	case circuits.AuthV2CircuitID:
		//nolint:gosec // fixed on main branch
		verifyAuthV2Sender(msg.From, token.ZkProof.PubSignals)
	default:
		return errors.Errorf("'%s' unknow circuit ID. can't verify msg sender", token.CircuitID)
	}
	return nil
}

func verifyAuthSender(from string, pubSignals []string) error {

	authPubSignals := circuits.AuthPubSignals{}

	if err := unmarshalPubSignals(&authPubSignals, pubSignals); err != nil {
		return err
	}

	id, err := core.IDFromInt(authPubSignals.UserID.BigInt())
	if err != nil {
		return err
	}

	if from != id.String() {
		return errors.Errorf("sender of message is not used for jwz token creation, expected: '%s' got: '%s", from,
			id.String())
	}

	return nil
}

func verifyAuthV2Sender(from string, pubSignals []string) error {

	authPubSignals := circuits.AuthV2PubSignals{}

	err := unmarshalPubSignals(&authPubSignals, pubSignals)
	if err != nil {
		return err
	}

	return checkSender(from, authPubSignals.UserID.BigInt())
}

func checkSender(from string, userID *big.Int) error {
	id, err := core.IDFromInt(userID)
	if err != nil {
		return err
	}

	if from != id.String() {
		return errors.Errorf("sender of message is not used for jwz token creation, expected: '%s' got: '%s", from,
			id.String())
	}
	return nil
}

func unmarshalPubSignals(obj circuits.PubSignalsUnmarshaller, pubSignals []string) error {
	bytePubsig, err := json.Marshal(pubSignals)
	if err != nil {
		return err
	}

	err = obj.PubSignalsUnmarshal(bytePubsig)
	if err != nil {
		return err
	}
	return nil
}

// MediaType for iden3comm that returns MediaTypeZKPMessage
func (p *ZKPPacker) MediaType() iden3comm.MediaType {
	return MediaTypeZKPMessage
}
