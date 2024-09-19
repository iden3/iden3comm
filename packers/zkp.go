package packers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-jwz/v2"
	"github.com/iden3/iden3comm/v2"
	"github.com/pkg/errors"
)

// MediaTypeZKPMessage is media type for jwz
const MediaTypeZKPMessage iden3comm.MediaType = "application/iden3-zkp-json"

// DataPreparerHandlerFunc registers the handler function for inputs preparation.
type DataPreparerHandlerFunc func(hash []byte, id *w3c.DID, circuitID circuits.CircuitID) ([]byte, error)

// Prepare function is responsible to call provided handler for inputs preparation
func (f DataPreparerHandlerFunc) Prepare(hash []byte, id *w3c.DID, circuitID circuits.CircuitID) ([]byte, error) {
	return f(hash, id, circuitID)
}

// VerificationHandlerFunc  registers the handler function for state verification.
type VerificationHandlerFunc func(id circuits.CircuitID, pubsignals []string) error

// Verify function is responsible to call provided handler for outputs verification
func (f VerificationHandlerFunc) Verify(id circuits.CircuitID, pubsignals []string) error {
	return f(id, pubsignals)
}

// StateVerificationFunc must verify pubsignals for circuit id
// TODO (illia-korotia): remove this type? Not used.
type StateVerificationFunc func(id circuits.CircuitID, pubsignals []string) error

// VerificationParams defined the verification function and the verification key for ZKP full verification
type VerificationParams struct {
	Key            []byte
	VerificationFn VerificationHandlerFunc
}

// NewVerificationParams creates new verification params
func NewVerificationParams(key []byte, verifier VerificationHandlerFunc) VerificationParams {
	return VerificationParams{
		Key:            key,
		VerificationFn: verifier,
	}
}

// ZKPPacker is packer that use JWZ
type ZKPPacker struct {
	Prover       map[jwz.ProvingMethodAlg]ProvingParams
	Verification map[jwz.ProvingMethodAlg]VerificationParams
}

// ProvingParams packer parameters for ZKP generation
type ProvingParams struct {
	DataPreparer DataPreparerHandlerFunc
	ProvingKey   []byte
	Wasm         []byte
}

// NewProvingParams defines the ZK proving parameters for ZKP generation
func NewProvingParams(dataPreparer DataPreparerHandlerFunc, provingKey, wasm []byte) ProvingParams {
	return ProvingParams{
		DataPreparer: dataPreparer,
		ProvingKey:   provingKey,
		Wasm:         wasm,
	}
}

// ZKPPackerParams is params for zkp packer
type ZKPPackerParams struct {
	SenderID         *w3c.DID
	ProvingMethodAlg jwz.ProvingMethodAlg
	iden3comm.PackerParams
}

// NewZKPPacker creates new zkp packer instance
func NewZKPPacker(provingParams map[jwz.ProvingMethodAlg]ProvingParams,
	verification map[jwz.ProvingMethodAlg]VerificationParams) *ZKPPacker {
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

	tokenStr, err := token.Prove(p.Prover[zkpParams.ProvingMethodAlg].ProvingKey,
		p.Prover[zkpParams.ProvingMethodAlg].Wasm)
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
		return nil, fmt.Errorf("message was packed with unsupported circuit `%s` and alg `%s`", token.CircuitID,
			token.Alg)
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

	if circuits.CircuitID(token.CircuitID) == circuits.AuthV2CircuitID {
		return verifyAuthV2Sender(msg.From, token)
	}

	return errors.Errorf("'%s' unknown circuit ID. can't verify msg sender", token.CircuitID)
}

func verifyAuthV2Sender(from string, token *jwz.Token) error {

	authPubSignals := circuits.AuthV2PubSignals{}

	err := unmarshalPubSignals(&authPubSignals, token.ZkProof.PubSignals)
	if err != nil {
		return err
	}
	challengeBytes, err := token.GetMessageHash()
	if err != nil {
		return err
	}

	challenge := new(big.Int).SetBytes(challengeBytes)
	did, err := core.ParseDIDFromID(*authPubSignals.UserID)

	if err != nil {
		return err
	}

	if from != did.String() {
		return errors.Errorf(
			"sender of message is not used for jwz token creation, expected: '%s' got: '%s", from,
			did.String())
	}

	if challenge.Cmp(authPubSignals.Challenge) != 0 {
		return errors.Errorf(
			"the challenge used for proof creation %s is not equal to the message hash %s",
			challenge.String(), authPubSignals.Challenge.String())
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

// DefaultZKPPakcerOption is a function that sets the default ZKP packer options
type DefaultZKPPakcerOption func(*defaultZKPPacker)

// WithAuthVerifyDelay sets the delay for the auth verification
func WithAuthVerifyDelay(delay time.Duration) DefaultZKPPakcerOption {
	return func(p *defaultZKPPacker) {
		p.authVerifyDelay = delay
	}
}

type defaultZKPPacker struct {
	resolvers       map[int]eth.Resolver
	authVerifyDelay time.Duration
}

// DefaultZKPPacker creates a default ZKP packer with the provided verification key and resolvers
func DefaultZKPPacker(verificationKey []byte, resolvers map[int]eth.Resolver, opts ...DefaultZKPPakcerOption) *ZKPPacker {
	def := &defaultZKPPacker{resolvers, time.Minute * 5}
	for _, opt := range opts {
		opt(def)
	}
	verifications := make(map[jwz.ProvingMethodAlg]VerificationParams)
	verifications[jwz.AuthV2Groth16Alg] = NewVerificationParams(verificationKey, def.defaultZkpPackerVerificationFn)
	return NewZKPPacker(nil, verifications)
}

func (d *defaultZKPPacker) defaultZkpPackerVerificationFn(id circuits.CircuitID, pubsignals []string) error {
	if id != circuits.AuthV2CircuitID {
		return errors.Errorf("circuit ID '%s' is not supported", id)
	}

	bytePubsig, err := json.Marshal(pubsignals)
	if err != nil {
		return errors.Errorf("error marshaling pubsignals: %v", err)
	}

	authPubSignals := circuits.AuthV2PubSignals{}
	err = authPubSignals.PubSignalsUnmarshal(bytePubsig)
	if err != nil {
		return errors.Errorf("error unmarshaling pubsignals: %v", err)
	}

	userDID, err := core.ParseDIDFromID(*authPubSignals.UserID)
	if err != nil {
		return errors.Errorf("error convertign userID '%s' to userDID: %v",
			authPubSignals.UserID.String(), err)
	}

	chainID, err := core.ChainIDfromDID(*userDID)
	if err != nil {
		return errors.Errorf("error extracting chainID from userDID '%s': %v",
			userDID.String(), err)
	}

	resolver := d.resolvers[int(chainID)]

	globalState := authPubSignals.GISTRoot.BigInt()
	globalStateInfo, err := resolver.ResolveGist(context.Background(), &services.ResolverOpts{GistRoot: globalState})
	if err != nil {
		return errors.Errorf("error getting global state info by state '%s': %v",
			globalState, err)
	}
	// if (big.NewInt(0)).Cmp(globalStateInfo.CreatedAtTimestamp) == 0 {
	// 	return errors.Errorf("root %s doesn't exist in smart contract",
	// 		globalState.String())
	// }
	if globalState.Cmp(globalStateInfo.Root) != 0 {
		return errors.Errorf("invalid global state info in the smart contract, expected root %s, got %s",
			globalState.String(), globalStateInfo.Root.String())
	}

	if (big.NewInt(0)).Cmp(globalStateInfo.ReplacedByRoot) != 0 &&
		time.Since(time.Unix(globalStateInfo.ReplacedAtTimestamp.Int64(), 0)) > d.authVerifyDelay {
		return errors.Errorf("global state is too old, replaced timestamp is %v",
			globalStateInfo.ReplacedAtTimestamp.Int64())
	}

	return nil
}
