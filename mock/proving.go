//go:build !no_jwz

// Package mock defines mocks for protocol testing
package mock

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-jwz/v2"
	"github.com/iden3/go-rapidsnark/types"
	joseprimitives "github.com/iden3/jose-primitives"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
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
		PubSignals: []string{
			"26240537881285303866959914873501215904100246541568629963310309506817331714",
			"16753929290617723035236297207980024500086356247597196241101864023287266506088",
			"6935795554508121074939204655265782244399347577736991410323391948936398259093",
		},
	}, nil
}

// PrepareAuthInputs returns mocked inputs for auth circuit
func PrepareAuthInputs(hash []byte, _ *w3c.DID, _ circuits.CircuitID) ([]byte, error) {
	challenge := new(big.Int).SetBytes(hash)

	// nolint:gosec // intentionally hardcoded key
	userMockedPK := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	mockedInputs := []byte(`{"genesisID":"26240537881285303866959914873501215904100246541568629963310309506817331714","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"authClaimIncMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"14269789266808968059169672911201921167953561300079987951824960759204067719875","challengeSignatureR8x":"20992633743481332091913653097095396906863961240425405184828226842777462122604","challengeSignatureR8y":"6273393852003225177156448231418255112053204171233395051223716406391798124538","challengeSignatureS":"2526580092966761964661422490382760858931103025833974942666750372883822638953","claimsTreeRoot":"9860409408344985873118363460916733946840214387455464863344022463808838582364","revTreeRoot":"0","rootsTreeRoot":"0","state":"1648710229725601204870171311149827592640182384459240511403224642152766848235","gistRoot":"6935795554508121074939204655265782244399347577736991410323391948936398259093","gistMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"28049899845899252156982726682342581898046855955053612508111669900571644418","gistMtpAuxHv":"20177832565449474772630743317224985532862797657496372535616634430055981993180","gistMtpNoAux":"0"}`)
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
func ResolveKeyID(keyID string) (jwk.Key, error) {
	recipientPrivKey, _ := ResolveEncPrivateKey(keyID)
	k, _ := recipientPrivKey.(*ecdsa.PrivateKey)
	importedKey, err := jwk.Import(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to import recipient public key: %w", err)
	}
	importedKey.Set(jwk.KeyIDKey, keyID)
	importedKey.Set(jwk.AlgorithmKey, jwa.ECDH_ES_A256KW().String())
	return importedKey, nil
}

// ResolveEncPrivateKey returns mocked private key
func ResolveEncPrivateKey(keyID string) (interface{}, error) {
	seed := new(big.Int)
	// key id should be integer
	seed.SetString(keyID, 16)

	recipientPrivKey := new(ecdsa.PrivateKey)
	recipientPrivKey.PublicKey.Curve = elliptic.P384()
	recipientPrivKey.D = seed
	recipientPrivKey.PublicKey.X, recipientPrivKey.PublicKey.Y = recipientPrivKey.PublicKey.Curve.ScalarBaseMult(seed.Bytes())
	return recipientPrivKey, nil
}

const (
	SenderKeyIdAuthCrypt    = "sender-key-id"
	RecipientKeyIdAuthCrypt = "recipient-key-id"
)

var (
	senderKey, _    = ecdh.P384().GenerateKey(rand.Reader)
	recipientKey, _ = ecdh.P384().GenerateKey(rand.Reader)

	PubResolverAuthCrypt = func(kid string) (interface{}, error) {
		if kid == SenderKeyIdAuthCrypt {
			return joseprimitives.Import(senderKey.PublicKey())
		}
		if kid == RecipientKeyIdAuthCrypt {
			return joseprimitives.Import(recipientKey.PublicKey())
		}
		return nil, errors.New("key not found")
	}

	PrivResolverAuthCrypt = func(kid string) (interface{}, error) {
		if kid == SenderKeyIdAuthCrypt {
			return senderKey, nil
		}
		if kid == RecipientKeyIdAuthCrypt {
			return recipientKey, nil
		}
		return nil, errors.New("key not found")
	}
)
