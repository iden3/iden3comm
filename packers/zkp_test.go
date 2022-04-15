package packers

import (
	"context"
	"encoding/json"
	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

type ProofGenMock struct {
}

func (p ProofGenMock) Generate(ctx context.Context,
	identifier *core.ID,
	request verifiable.ProofRequest) (*verifiable.ZKProof, error) {
	return &verifiable.ZKProof{
		Proof: &verifiable.ProofData{
			A:        []string{"1", "2"},
			B:        [][]string{{"1,2"}, {"1,3"}},
			C:        []string{"1", "2"},
			Protocol: "groth16",
		},
		PubSignals: []string{
			"19999688707115363375798349135216882950137172827530523694906852148073727847759", "11111111111111", "11111111111111111",
		},
	}, nil
}
func (p ProofGenMock) VerifyZKProof(ctx context.Context, zkp *verifiable.ZKProof, circuitType string) (bool, error) {
	return true, nil
}

func TestZKPPacker_Pack(t *testing.T) {

	p := NewZKPPacker("ZKP-GROTH16", circuits.AuthCircuitID, ProofGenMock{})

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-response/v1","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	pp := &PlainMessagePacker{}
	message, err := pp.Unpack(msgBytes)
	assert.Nil(t, err)
	id, _ := core.IDFromString("1182P96d4eBnRAUWvGyj5QiPLL5U1TiNyJwcspt478")
	b, err := p.Pack(message, &id)
	assert.Nil(t, err)

	t.Log(string(b))
}

func TestPlainMessagePacker_Unpack(t *testing.T) {
	p := NewZKPPacker("ZKP-GROTH16", circuits.AuthCircuitID, ProofGenMock{})
	msg := []byte(`{"payload":"eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24tcmVzcG9uc2UvdjEiLCJib2R5Ijp7InNjb3BlIjpbeyJ0eXBlIjoiemVyb2tub3dsZWRnZSIsImNpcmN1aXRfaWQiOiJhdXRoIiwicHViX3NpZ25hbHMiOlsiMSIsIjE4MzExNTYwNTI1MzgzMzE5NzE5MzExMzk0OTU3MDY0ODIwMDkxMzU0OTc2MzEwNTk5ODE4Nzk3MTU3MTg5NTY4NjIxNDY2OTUwODExIiwiMzIzNDE2OTI1MjY0NjY2MjE3NjE3Mjg4NTY5NzQyNTY0NzAzNjMyODUwODE2MDM1NzYxMDg0MDAyNzIwMDkwMzc3MzUzMjk3OTIwIl0sInByb29mX2RhdGEiOnsicGlfYSI6WyIxMTEzMDg0MzE1MDU0MDc4OTI5OTQ1ODk5MDU4NjAyMDAwMDcxOTI4MDI0NjE1Mzc5Nzg4Mjg0MzIxNDI5MDU0MTk4MDUyMjM3NTA3MiIsIjEzMDA4NDE5MTI5NDM3ODE3MjMwMjIwMzIzNTU4MzY4OTM4MzExMzI5MjA3ODM3ODg0NTU1MzE4MzgyNTQ0NjU3ODQ2MDU3NjI3MTMiLCIxIl0sInBpX2IiOltbIjIwNjE1NzY4NTM2OTg4NDM4MzM2NTM3Nzc3OTA5MDQyMzUyMDU2MzkyODYyMjUxNzg1NzIyNzk2NjM3NTkwMjEyMTYwNTYxMzUxNjU2IiwiMTAzNzExNDQ4MDYxMDc3Nzg4OTA1Mzg4NTc3MDA4NTUxMDg2Njc2MjIwNDIyMTUwOTY5NzE3NDcyMDMxMDU5OTc0NTQ2MjU4MTQwODAiXSxbIjE5NTk4NTQxMzUwODA0NDc4NTQ5MTQxMjA3ODM1MDI4NjcxMTExMDYzOTE1NjM1NTgwNjc5Njk0OTA3NjM1OTE0Mjc5OTI4Njc3ODEyIiwiMTUyNjQ1NTMwNDU1MTcwNjU2NjkxNzE1ODQ5NDM5NjQzMjIxMTczOTc2NDUxNDcwMDY5MDkxNjc0Mjc4MDk4Mzc5Mjk0NTgwMTI5MTMiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NDQzMzA5Mjc5ODI1NTA4ODkzMDg2MjUxMjkwMDAzOTM2OTM1MDc3MzQ4NzU0MDk3NDcwODE4NTIzNTU4MDgyNTAyMzY0ODIyMDQ5IiwiMjk4NDE4MDIyNzc2NjA0ODEwMDUxMDEyMDQwNzE1MDc1MjA1MjMzNDU3MTg3NjY4MTMwNDk5OTU5NTU0NDEzODE1NTYxMTk2MzI3MyIsIjEiXSwicHJvdG9jb2wiOiIifX1dfX0","protected":"eyJhbGciOiJaS1AtR1JPVEgxNiIsImNpcmN1aXRJZCI6ImF1dGgiLCJjcml0IjoiY2lyY3VpdElkIn0","signature":"eyJwcm9vZiI6eyJwaV9hIjpbIjEiLCIyIl0sInBpX2IiOltbIjEsMiJdLFsiMSwzIl1dLCJwaV9jIjpbIjEiLCIyIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIxOTk5OTY4ODcwNzExNTM2MzM3NTc5ODM0OTEzNTIxNjg4Mjk1MDEzNzE3MjgyNzUzMDUyMzY5NDkwNjg1MjE0ODA3MzcyNzg0Nzc1OSIsIjExMTExMTExMTExMTExIiwiMTExMTExMTExMTExMTExMTEiXX0"}`)

	b, err := p.Unpack(msg)
	assert.Nil(t, err)

	bodyBytes, err := b.GetBody().(json.RawMessage).MarshalJSON()
	assert.Nil(t, err)

	t.Log(string(bodyBytes))
}

func TestZKPPacker_PrepareMessageHash(t *testing.T) {

	p := NewZKPPacker(AlgZKPGroth16, circuits.AuthCircuitID, ProofGenMock{})

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = math.MaxUint8
	}
	h, err := p.PrepareMessageHash(msg)
	assert.Nil(t, err)
	assert.True(t, utils.CheckBigIntInField(h))
}
