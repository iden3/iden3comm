package packers

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

const (
	messageToEncode = `{"id":"123","type":"https://iden3-communication.io/authorization/1.0/response","from":"119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ","body":{"scope":[{"type":"zeroknowledge","circuitId":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`
)

var (
	senderKey, _    = ecdh.P256().GenerateKey(rand.Reader)
	recipientKey, _ = ecdh.P256().GenerateKey(rand.Reader)
)

func TestAuthCry(t *testing.T) {
	a := Authcrypt{
		kr: func(kid string) (interface{}, error) {
			return senderKey, nil
		},
	}

	recipient, err := echdToECDSA(recipientKey.PublicKey())
	if err != nil {
		t.Fatalf("failed to convert recipient key to ECDH: %s", err)
	}

	jwetoken, err := a.Encrypt(jose.JSONWebKey{
		Key: recipient,
	}, "sender", []byte(messageToEncode))
	if err != nil {
		t.Fatalf("failed to encrypt message: %s", err)
	}

	a = Authcrypt{
		kr: func(kid string) (interface{}, error) {
			return recipientKey, nil
		},
	}

	payload, err := a.Decrypt(jwetoken, senderKey.PublicKey())
	if err != nil {
		t.Fatalf("failed to decrypt message: %s", err)
	}

	require.Equal(t, messageToEncode, string(payload))
}
