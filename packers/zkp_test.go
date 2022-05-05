package packers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits"
	circuitsTesting "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/jwz"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

type prover struct {
}

func (p *prover) PrepareAuthInputs(hash []byte, id *core.ID, circuitID circuits.CircuitID) (circuits.InputsMarshaller, error) {
	return MockPrepareAuthInputs(hash, id, circuitID)
}
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
func MockPrepareAuthInputsV2(hash []byte, id *core.ID, circuitID circuits.CircuitID) (circuits.InputsMarshaller, error) {
	return circuits.AuthInputs{}, nil
}
func TestZKPPacker_Pack(t *testing.T) {

	p := NewZKPPacker(jwz.ProvingMethodGroth16AuthInstance, func(hash []byte, id *core.ID, circuitID circuits.CircuitID) (circuits.InputsMarshaller, error) {
		return MockPrepareAuthInputs(hash, id, circuitID)
	})

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-response/v1","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)
	id, _ := core.IDFromString("119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ")
	b, err := p.Pack(msgBytes, &id)
	assert.Nil(t, err)

	token, err := jwz.Parse(string(b))
	assert.Nil(t, err)

	outs := circuits.AuthPubSignals{}
	err = token.ParsePubSignals(&outs)
	assert.Nil(t, err)

	assert.EqualValues(t, id.String(), outs.UserID.String())

	t.Log(string(b))
}

func TestPlainMessagePacker_Unpack(t *testing.T) {
	p := NewZKPPacker(jwz.ProvingMethodGroth16AuthInstance, (&prover{}).PrepareAuthInputs)
	msgZKP := []byte(`{"payload":"eyJ0eXAiOiIiLCJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24tcmVzcG9uc2UvdjEiLCJib2R5Ijp7InNjb3BlIjpbeyJ0eXBlIjoiemVyb2tub3dsZWRnZSIsImNpcmN1aXRfaWQiOiJhdXRoIiwicHViX3NpZ25hbHMiOlsiMSIsIjE4MzExNTYwNTI1MzgzMzE5NzE5MzExMzk0OTU3MDY0ODIwMDkxMzU0OTc2MzEwNTk5ODE4Nzk3MTU3MTg5NTY4NjIxNDY2OTUwODExIiwiMzIzNDE2OTI1MjY0NjY2MjE3NjE3Mjg4NTY5NzQyNTY0NzAzNjMyODUwODE2MDM1NzYxMDg0MDAyNzIwMDkwMzc3MzUzMjk3OTIwIl0sInByb29mX2RhdGEiOnsicGlfYSI6WyIxMTEzMDg0MzE1MDU0MDc4OTI5OTQ1ODk5MDU4NjAyMDAwMDcxOTI4MDI0NjE1Mzc5Nzg4Mjg0MzIxNDI5MDU0MTk4MDUyMjM3NTA3MiIsIjEzMDA4NDE5MTI5NDM3ODE3MjMwMjIwMzIzNTU4MzY4OTM4MzExMzI5MjA3ODM3ODg0NTU1MzE4MzgyNTQ0NjU3ODQ2MDU3NjI3MTMiLCIxIl0sInBpX2IiOltbIjIwNjE1NzY4NTM2OTg4NDM4MzM2NTM3Nzc3OTA5MDQyMzUyMDU2MzkyODYyMjUxNzg1NzIyNzk2NjM3NTkwMjEyMTYwNTYxMzUxNjU2IiwiMTAzNzExNDQ4MDYxMDc3Nzg4OTA1Mzg4NTc3MDA4NTUxMDg2Njc2MjIwNDIyMTUwOTY5NzE3NDcyMDMxMDU5OTc0NTQ2MjU4MTQwODAiXSxbIjE5NTk4NTQxMzUwODA0NDc4NTQ5MTQxMjA3ODM1MDI4NjcxMTExMDYzOTE1NjM1NTgwNjc5Njk0OTA3NjM1OTE0Mjc5OTI4Njc3ODEyIiwiMTUyNjQ1NTMwNDU1MTcwNjU2NjkxNzE1ODQ5NDM5NjQzMjIxMTczOTc2NDUxNDcwMDY5MDkxNjc0Mjc4MDk4Mzc5Mjk0NTgwMTI5MTMiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NDQzMzA5Mjc5ODI1NTA4ODkzMDg2MjUxMjkwMDAzOTM2OTM1MDc3MzQ4NzU0MDk3NDcwODE4NTIzNTU4MDgyNTAyMzY0ODIyMDQ5IiwiMjk4NDE4MDIyNzc2NjA0ODEwMDUxMDEyMDQwNzE1MDc1MjA1MjMzNDU3MTg3NjY4MTMwNDk5OTU5NTU0NDEzODE1NTYxMTk2MzI3MyIsIjEiXSwicHJvdG9jb2wiOiIifX1dfX0=","protected":"eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIn0=","header":{"alg":"groth16","circuitId":"auth","crit":["circuitId"],"typ":"application/iden3-zkp-json"},"zkp":"eyJwcm9vZiI6eyJwaV9hIjpbIjUzMDI2MjQ4NDgxMTg0NDQzNTk1MDcyMDAxNzkxMDgwNzUxNjIyOTcxMjQ2MTgwMzY1ODU0MjE3NjM0MzI1Nzk2MzE5ODcwNjQ5MzYiLCIxMzk5NjUxMzczMzEwMDg1MTc3Mzk2Njc3MzU2MTMyOTI1NzIzMzA5NzUxNDE1NTM4MjM4MDk1NDczMDU5MzgwMzk3NjUwOTgyNDM1NSIsIjEiXSwicGlfYiI6W1siNzA2NTMzNzY1MzIyMDU2OTE0MTc2MjgwMzM0ODkyOTk2OTU0MzU4NDQxMjQ1OTU1MzczOTQwMTkzMzcwNDMwNzYwNTMyOTk4NjY0MSIsIjE0MDcxMjk3NzYxNjkzNDY2NzYyMTg5MzQ1ODQzNjE0MjA5Njc1NzIxMzAxNDk0ODc3MDUzNjc4NTU4Mjk5MzQ3MjYyMTE2MTUxNjYwIl0sWyIyMDc2MTkzNjI4MDU2MTk4MzI5NTQyNTkzNDkxMjc2MDE1MjQ1MTEzOTQwMDE3ODY3ODIyMzg2NjQxNzYzNzIxODM2MTM5NzIyNDU2MyIsIjEyNzgwNjUwNDQ3MTU5MjkwMDQwMjcxODU2NzQzNjAxMjc2OTI1OTY0OTIxODA3MDc1Mjg0OTI0NDY2NTA5OTc4ODg2NTE5ODkzNDQyIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxMDQ3MzkzMzAzMjc4Nzc2NDc2MDk2NjU4MTgzMTA5OTk3NjU3MDQ3MjY3ODU3Nzc2NTAxNjg5MTc1NzUwMjM2MTgyMDQ5Mjg3ODQzOSIsIjEyMjY1MDAxNzk0OTEwMzgyODQ4MDUxODA0NzY5Nzc1NTE1ODY2NDAyNjA5MzA1ODIxMDA5NTE2OTE5MTIxNzgyMjA4NzI0MTU3NjE1IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMTQzNDA3MDgyNzQ5NDc4Mzc4NDk5MzE3MjU2MDA3NjI4NTAwMjM3OTU4ODEzNzU3OTg0NTk3NDM1MTcyNjY1NDMyMzc3MzcyOTQwMzAiLCIxODY1NjE0NzU0NjY2Njk0NDQ4NDQ1Mzg5OTI0MTkxNjQ2OTU0NDA5MDI1ODgxMDE5MjgwMzk0OTUyMjc5NDQ5MDQ5MzI3MTAwNTMxMyIsIjM3OTk0OTE1MDEzMDIxNDcyMzQyMDU4OTYxMDkxMTE2MTg5NTQ5NTY0Nzc4OTAwNjY0OTc4NTI2NDczODE0MTI5OTEzNTQxNDI3MiJdfQ=="}`)
	iden3msg, err := p.Unpack(msgZKP)
	assert.Nil(t, err)
	msgBytes, err := json.Marshal(iden3msg)
	assert.Nil(t, err)
	fmt.Println(string(msgBytes))
	bodyBytes, err := iden3msg.GetBody().(json.RawMessage).MarshalJSON()
	assert.Nil(t, err)

	t.Log(string(bodyBytes))
}
