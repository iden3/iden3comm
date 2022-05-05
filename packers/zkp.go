package packers

import (
	"encoding/json"
	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/iden3comm"
	"github.com/iden3/jwz"
	"github.com/pkg/errors"
)

// MediaTypeZKPMessage is media type for jwz
const MediaTypeZKPMessage iden3comm.MediaType = "application/iden3-zkp-json"

// AuthDataPreparerHandlerFunc registers the handler function for inputs preparation.
type AuthDataPreparerHandlerFunc func(hash []byte, id *core.ID, circuitID circuits.CircuitID) (circuits.InputsMarshaller, error)

// Prepare function is responsible to call provided handler for inputs preparation
func (f AuthDataPreparerHandlerFunc) Prepare(hash []byte, id *core.ID, circuitID circuits.CircuitID) (circuits.InputsMarshaller, error) {
	return f(hash, id, circuitID)
}

// ZKPPacker is  packer that use JWZ
type ZKPPacker struct {
	ProvingMethod    jwz.ProvingMethod
	AuthDataPreparer AuthDataPreparerHandlerFunc
}

// NewZKPPacker creates new instance of zkp Packer.
// Pack works only with a specific proving Method
// Unpack is universal function that supports all proving method defined in jwz.
func NewZKPPacker(provingMethod jwz.ProvingMethod, authDataPreparer AuthDataPreparerHandlerFunc) *ZKPPacker {

	return &ZKPPacker{
		ProvingMethod:    provingMethod,
		AuthDataPreparer: authDataPreparer,
	}
}

// Pack returns packed message to transport envelope with a zero knowledge proof in JWZ full serialized format
func (p *ZKPPacker) Pack(payload []byte, senderID *core.ID) ([]byte, error) {

	// create hash of message
	var err error
	var token *jwz.Token

	token, err = jwz.NewWithPayload(p.ProvingMethod, payload)
	if err != nil {
		return nil, err
	}

	err = token.WithHeader(jwz.HeaderType, MediaTypeZKPMessage)
	if err != nil {
		return nil, err
	}

	hash, err := token.GetMessageHash()
	if err != nil {
		return nil, err
	}

	inputs, err := p.AuthDataPreparer.Prepare(hash, senderID, circuits.CircuitID(token.CircuitID))
	if err != nil {
		return nil, err
	}

	// TODO: get proving from circuits package for specific circuit
	var provingKey []byte
	err = token.Prove(inputs, provingKey)
	if err != nil {
		return nil, err
	}

	tokenStr, err := token.FullSerialize()
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

	verificationKey, err := circuits.GetVerificationKey(circuits.CircuitID(token.CircuitID))
	if err != nil {
		return nil, err
	}

	err = token.Verify(verificationKey)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("zk proof is not valid")
	}

	var msg iden3comm.BasicMessage
	err = json.Unmarshal(token.GetPayload(), &msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &msg, err
}

// MediaType for iden3comm that returns MediaTypeZKPMessage
func (p *ZKPPacker) MediaType() iden3comm.MediaType {
	return MediaTypeZKPMessage
}
