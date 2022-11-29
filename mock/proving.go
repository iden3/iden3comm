// Package mock defines mocks for protocol testing
package mock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-jwz"
	"github.com/iden3/go-rapidsnark/types"
	"gopkg.in/square/go-jose.v2"
)

// ProvingMethodGroth16AuthV2 proving method to avoid using of proving key and wasm files
type ProvingMethodGroth16AuthV2 struct {
	jwz.ProvingMethodAlg
}

// Alg returns current zk alg
func (m *ProvingMethodGroth16AuthV2) Alg() string {
	return m.ProvingMethodAlg.Alg
}

// CircuitID returns name of circuit
func (m *ProvingMethodGroth16AuthV2) CircuitID() string {
	return m.ProvingMethodAlg.CircuitID
}

// Verify return no error for any proof
func (m *ProvingMethodGroth16AuthV2) Verify(_ []byte, _ *types.ZKProof, _ []byte) error {
	return nil
}

// Prove generates proof using auth circuit and groth16 alg, checks that proven message hash is set as a part of circuit specific inputs
func (m *ProvingMethodGroth16AuthV2) Prove(_, _, _ []byte) (*types.ZKProof, error) {

	return &types.ZKProof{
		Proof: &types.ProofData{
			A:        nil,
			B:        nil,
			C:        nil,
			Protocol: "groth16",
		},
		PubSignals: []string{"19229084873704550357232887142774605442297337229176579229011342091594174977", "6110517768249559238193477435454792024732173865488900270849624328650765691494", "1243904711429961858774220647610724273798918457991486031567244100767259239747"},
	}, nil
}

// PrepareAuthInputs returns mocked inputs for auth circuit
func PrepareAuthInputs(hash []byte, _ *core.DID, _ circuits.CircuitID) ([]byte, error) {
	challenge := new(big.Int).SetBytes(hash)

	userMockedPK := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	mockedInputs := []byte(`{"genesisID":"19229084873704550357232887142774605442297337229176579229011342091594174977","profileNonce":"0","authClaim":["301485908906857522017021291028488077057","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6110517768249559238193477435454792024732173865488900270849624328650765691494","challengeSignatureR8x":"10923900855019966925146890192107445603460581432515833977084358496785417078889","challengeSignatureR8y":"16158862443157007045624936621448425746188316255879806600364391221203989186031","challengeSignatureS":"51416591880507739389339515804072924841765472826035808894700970942045022090","claimsTreeRoot":"5156125448952672817978035354327403409438120028299513459509442000229340486813","revTreeRoot":"0","rootsTreeRoot":"0","state":"13749793311041076104545663747883540987785640262360452307923674522221753800226","gistRoot":"1243904711429961858774220647610724273798918457991486031567244100767259239747","gistMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"1","gistMtpAuxHv":"1","gistMtpNoAux":"0"}`)
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(userMockedPK)); err != nil {
		return nil, err
	}
	sig := k.SignPoseidon(challenge)
	var i map[string]interface{}

	err := json.Unmarshal(mockedInputs, &i)
	if err != nil {
		return nil, err
	}
	i["challengeSignatureS"] = sig.S.String()
	i["challengeSignatureR8x"] = sig.R8.X.String()
	i["challengeSignatureR8y"] = sig.R8.Y.String()

	j, err := json.Marshal(i)
	return j, err
}

// VerifyState return no error always
func VerifyState(_ circuits.CircuitID, _ []string) error {
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
