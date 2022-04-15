package packers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"math/big"
)

// MediaTypeZKPMessage is media type for jwz
const MediaTypeZKPMessage iden3comm.MediaType = "application/iden3-zkp-json"

type zkProver interface {
	Generate(ctx context.Context,
		identifier *core.ID,
		request verifiable.ProofRequest) (*verifiable.ZKProof, error)
	VerifyZKProof(ctx context.Context, zkp *verifiable.ZKProof, circuitType string) (bool, error)
}

// ZKPPacker is  packer that use JWS format but with zero knowledge proof
type ZKPPacker struct {
	zkpAlg    string
	circuitID circuits.CircuitID
	zk        zkProver
}

// NewZKPPacker creates new instance of zkp Packer
func NewZKPPacker(zkpAlg string, circuitID circuits.CircuitID, zk zkProver) *ZKPPacker {
	return &ZKPPacker{
		zkpAlg:    zkpAlg,
		circuitID: circuitID,
		zk:        zk,
	}
}

// AlgZKPGroth16 is algorithm for JWZ
const AlgZKPGroth16 = "ZKP-GROTH16"

// Pack returns packed message to transport envelope with a zero knowledge proof in JWZ full serialized format
func (p *ZKPPacker) Pack(payload iden3comm.Iden3Message, senderID *core.ID) ([]byte, error) {

	// create hash of message

	serialized, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	hash, err := p.PrepareMessageHash(serialized)
	if err != nil {
		return nil, err
	}

	proofBytes, err := p.prepareZKProof(context.Background(), senderID, hash)
	if err != nil {
		return nil, err
	}

	jwz := iden3comm.JSONWebZeroknowledge{
		Payload: serialized,
		ZKP:     proofBytes,
	}
	err = jwz.SetHeader(p.zkpAlg, p.circuitID, string(MediaTypeZKPMessage))
	if err != nil {
		return nil, err
	}
	return jwz.FullSerialize()
}

// Unpack returns unpacked message from transport envelope with verification of zeroknowledge proof
func (p *ZKPPacker) Unpack(envelope []byte) (iden3comm.Iden3Message, error) {

	jws, err := jose.ParseSigned(string(envelope))
	if err != nil {
		return nil, err
	}
	payload := jws.UnsafePayloadWithoutVerification()

	signature := jws.Signatures[0]

	// get headers

	alg := signature.Header.Algorithm
	circuitID := signature.Header.ExtraHeaders["circuitId"].(string)
	if alg != p.zkpAlg {
		return nil, errors.Errorf("%s algorithm is not supported by zkp packer", alg)
	}
	if circuits.CircuitID(circuitID) != p.circuitID {
		return nil, errors.Errorf("%s circuit is not supported by zkp packer", circuitID)
	}

	var proof *verifiable.ZKProof

	err = json.Unmarshal(signature.Signature, &proof)
	if err != nil {
		return nil, err
	}
	isProofValid, err := p.zk.VerifyZKProof(context.Background(), proof, circuitID)
	if err != nil {
		return nil, err
	}
	if !isProofValid {
		return nil, errors.New("zk proof is not valid")
	}

	// get circuit public schema

	circuit, err := circuits.GetCircuit(p.circuitID)
	if err != nil {
		return nil, err
	}
	publicSchemaJSON := circuit.GetPublicSignalsSchema()
	var schemaPublicOutputs map[string]int
	err = json.Unmarshal([]byte(publicSchemaJSON), &schemaPublicOutputs)
	if err != nil {
		return nil, err
	}

	// TODO: change to 'metadata'
	metadataHashIndex := schemaPublicOutputs["challenge"]

	if len(proof.PubSignals) != len(schemaPublicOutputs) {
		return nil, errors.New("public signals count in proof is not corresponding to schema")
	}

	hashSignal := proof.PubSignals[metadataHashIndex]

	hashSignalBigInt, ok := new(big.Int).SetString(hashSignal, 10)
	if !ok {
		return nil, errors.New("can't convert a signal")
	}

	// verify that message hash is one that is provided in the proof

	messageHash, err := p.PrepareMessageHash(payload)
	if err != nil {
		return nil, err
	}

	if messageHash.Cmp(hashSignalBigInt) != 0 {
		return nil, errors.New("has of message data is not equal to metadata if proof signal")
	}

	var msg iden3comm.BasicMessage
	err = json.Unmarshal(payload, &msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &msg, err
}

func (p *ZKPPacker) prepareZKProof(ctx context.Context, id *core.ID, hash *big.Int) ([]byte, error) {

	proof, err := p.zk.Generate(ctx, id, &verifiable.ZeroKnowledgeProofRequest{CircuitID: string(p.circuitID), Challenge: hash, Rules: nil})
	if err != nil {
		return nil, err
	}
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return proofBytes, err
}

// PrepareMessageHash return hash of the message that is used in authentication circuit
func (p *ZKPPacker) PrepareMessageHash(message []byte) (*big.Int, error) {

	// 1. sha256 hash
	h := sha256.New()
	_, err := h.Write(message)
	if err != nil {
		return nil, err
	}
	b := h.Sum(nil)

	// 2. swap hash before hashing

	bs := utils.SwapEndianness(b)
	bi := new(big.Int).SetBytes(bs)

	// 3. check if it's in field
	m := new(big.Int)
	if utils.CheckBigIntInField(bi) {
		m = bi
	} else {
		bi.DivMod(bi, constants.Q, m)
	}

	// 2. poseidon

	res, err := poseidon.Hash([]*big.Int{m})

	if err != nil {
		return nil, err
	}
	return res, err
}

// MediaType for iden3comm
func (p *ZKPPacker) MediaType() iden3comm.MediaType {
	return MediaTypeZKPMessage
}
