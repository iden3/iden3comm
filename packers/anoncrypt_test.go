package packers

import (
	"encoding/json"
	"github.com/iden3/iden3comm/mock"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestAnoncryptPacker_Pack(t *testing.T) {
	var msgBytes = []byte(`{"id":"123","type":"https://iden3-communication.io/authorization/1.0/response","from":"119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	privKey, err := mock.ResolveEncPrivateKey(mock.MockRecipientKeyID)
	require.NoError(t, err)

	key, err := mock.ResolveKeyID(mock.MockRecipientKeyID)
	require.NoError(t, err)

	anonPacker := AnoncryptPacker{}
	ciphertext, err := anonPacker.Pack(msgBytes, AnoncryptPackerParams{
		RecipientKey: &key,
	})
	require.NoError(t, err)
	require.NotEqual(t, 0, len(ciphertext))

	// decrypt in user side.
	jwe, err := jose.ParseEncrypted(string(ciphertext))
	require.NoError(t, err)
	require.EqualValues(t, jwe.Header.ExtraHeaders[jose.HeaderType], MediaTypeEncryptedMessage)

	iden3BytesMsg, err := jwe.Decrypt(privKey)
	require.NoError(t, err)
	require.Equal(t, msgBytes, iden3BytesMsg)
}
func TestAnoncryptPacker_Unpack(t *testing.T) {
	var msgBytes = []byte(`{"id":"123","type":"https://iden3-communication.io/authorization/1.0/response","from":"119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	jwe := `eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJvSGhaR0VHY3V0ZnhkbS1xU1U5N2hpMGNDY0x5MXliSWxMemRPSmxOTW1RIiwieSI6Ill4T3p3RlNtNWNJVGc4TkE0UFhrODJfTWN2RzJtWlh6cm14bHNTUUhaZ1UifSwia2lkIjoiMTIzMjQ1MzY2NDc1NzM0IiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLWVuY3J5cHRlZC1qc29uIn0.bPY8vqgL4l1rBDtbQSAoyRbH1l4mwfoVefDvmJrXG7GenNxVsagTpx-rAtlQZsgCHhptTBw3ZhSq7wf3n-aaceM0hfoKAkxz.DWDyaIAzcpSfTd8gjNy68Q.Vj-rx3V4TJQ__ZFKJ2E8TFHJ9QuHDiPBl3sdt6SCPIS26fAwWpS60tWEfTXNzR01LxnOU5MqJEIwYOhbbk8PrTwjE5UcorqcY8DPGP8CAforyLchaOMdtiFEbuFmAZg1PyHRNYlh6Nti5RdNQ_ZOr90oLMXEIHHM5fenr2aeNAWVz2LM6jkPOo_zalXT20FxPK-1bzmaLBdgvh-wJ-IrGgXqFCqquj9XFiy9QPY_8yJAqAlU0YeamL81VAdfCC69gmeklM3GQdJj5bhkN-d2BH9MKavrg58qpr8wq3geDIB5MLQWkY6XBiKI7F04iCNVlCViY4bistQwT5kM-hmjG8KDiS4JY4s7Ek0061JKrVC1yoRBiVdt6BboGcevRNFf2lgsyoHwoK-s1UM-Xbl5C5AQ-pxnDVTxyjkXuYfL44xT2Hxw9nqWB4hgWtHXlGROXe7xB285ci0hKrmzdJb19tVbZrqblafcE9686KAIu1kPiITY70cuUKfm0_LkvKMtz4JzMgfMDd5dyheNWjw6lExLtlDuBdqnOzlR4Q1cstSQT1CSvlmr-JerHXwsSHVKf6bRXH0ePOTk2fM7wmPJUkv95SBlZ5BfAg_0z6tQZsW4hEU3cQvITsel77ifRr_74giY_9l35eX5lZL210MhJHbHGwV0GSZMgMaOisJzKe_upgXKtjfrMISMs-IyBnmJx0VWEw4yS9CP9mM649xjWIc62oqVAMk6UVq7I8zicp4HhjO-QRipfGgsqLs-AGo2JUwhGWbI9uaYeMn6UlMg67jh-Kx4mwrx_vz291Z4lREUewNN8uzLsELwCl-1dWOP2hQLn2lYYD8JKD-4AGnOC3lcGIzk7UeJoTve9jU9KqWqk73gI4k0bRMLZ-h4KDyyD1P4h-kALr-XVx3mcc_N_QsaRZWF74aCA8GkMdvbYxVTQThuKO7XjlWGO48LCnuBIBgbcrTnXGNGRRCPyompaftE_1l45IRKO18dZo7qr62l7ett_aNbRgG-1P_G3pe-_dnpmcX7T3dsLGQNcgaQgnY7Gw1yfU1XGjv8yt9wSWnQxdwRvOsU7MFKJZPurUD2qJJtd73cQR9z3T0odTjO_TeOgXuYmSoi87tXYoGcXBqqLHvq913QEKeKbQQ7w9Uih0s_MLbTUDfTAK2PHksduaB5sdIPomyQ2qYthsb45pjX0DbsW-bmxJNhCEEm7y0yaisT8lzvSgwotBMK_cvGuAdNJbPeSsSmZxAXifpoaVgbbTZ2ZH-FsHAqYeiVYDL6HFGjOtJwar2YGtzqLaDNrz3qHpg_RwWW-t_Oz6_pXs9443irO56pAop0xVhheYhL-sG3AFt0frQ4geP-WXPpGu8m0ZkIdo-uyhuNjaafCzsDp-6O3uvUXjZ1QawaDBVwslOpbi10t8qUYmcDmTjavQtmtvrbeja6lhTEDOwBLninTmI2QPrd5qz8zNdcLaKE.aWO2pNsrgej-fMQwkyyvVsRiqtKZUrv0QhInp0-VpW4`
	anonPacker := NewAnoncryptPacker(mock.ResolveEncPrivateKey)
	iden3BytesMsg, err := anonPacker.Unpack([]byte(jwe))
	require.NoError(t, err)
	actualMsgBytes, err := json.Marshal(iden3BytesMsg)

	require.NoError(t, err)
	require.JSONEq(t, string(msgBytes), string(actualMsgBytes))

}
