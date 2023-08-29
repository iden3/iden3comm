package packers

import (
	"encoding/json"
	"testing"

	"github.com/iden3/iden3comm/v2/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-jose/go-jose.v2"
)

func TestAnoncryptPacker_Pack(t *testing.T) {
	var msgBytes = []byte(`{"id":"123","type":"https://iden3-communication.io/authorization/1.0/response","from":"119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ","body":{"scope":[{"type":"zeroknowledge","circuitId":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

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
	var msgBytes = []byte(`{"id":"123","type":"https://iden3-communication.io/authorization/1.0/response","from":"119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ","body":{"scope":[{"type":"zeroknowledge","circuitId":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	jwe := `eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJfb1p6cnVyVG5WV0xBS2RKVFhxWE5WQUszTHBaSzR6NFNVNWk1ZEZ6bWQwIiwieSI6InNZR19uUXd3MU14aUp0Q3VBTm1kelJPaUtwNDNTZFVsTy1uZzltLTc2eFkifSwia2lkIjoiMTIzNDU2Nzg5IiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLWVuY3J5cHRlZC1qc29uIn0.ic5CHum0tGjoAfOnu8B45rdKwAIOgqQ8TPaQWbYMxdfaxDX1bKmyVoYaCgFle4fJb1_0_Vl0v9QEuAozH8lC51pCWvbvNkMn.D9h3LFsHk_VX9LlxhQNfOQ.wsdTsSK-ftl_sTFZG-wzBJfT3g3Ok4DnBSeZNifimd9yg0YYfIw4yytgyXFiKeupMGe4wGskw-8wxLCxYOtAmgSpr8_LAEQCq9oLgKgZZco1UhNJCcsU1QCNgeIy2TNJ8zQsVedJJwA8G7tH3vFLA3W5rj_Pj_5TStt5H0gzxKIo4g4pBdamr1um6P4PWF-kn8Jo3KXX5Yf487gfzvz7M2BXx2rCpuKR7rG9mglOlwKH4UVwPuDIxBYGmk5IQJr1y3csig7uszfdYItX2gwoLtN1rZkjOV0zs7mfr3jjvrNr7u-E8NuR3Xsj5IWz8aKMdQ5vqx3v0woJAXLj0afYYz8gqDGQrhsaXf-VSX24oIXoWoiWBLH0vrnRx2HdqSXorNse4WZc51KQtD489JkaXWsZNWTMLS9YOcPkGW4UM8tJX_9eMcI8_8oCVZ8xWlJRMZmvTOtgjW_qCs-5zxGba9CBRsH0Qk0QsKYkuMBbQUejjgfVn1yOYgLgoTA0dN-5TUSj7wLdDkP2fB6IUL5cl_YpvMNHO4919Lp7KQLFwxU5XlmHp8pUeU9DBs37gytrC-B84zmUmZ40_K4zhfnROtTzfO4WxhukDkxWHSLWO5_9fMxsUTfwmHaPiEw_P095yUVZSGmq5FnXLcF9kNwxklkVyRj7G24ugkY3boPm2eDBzQPWkgvcAdlUMWuitWwYimDlafwZqRqmkNWFoMTDHcTwOXxM29glMhya6s_mAJwAeTLKuKIvVRRTEQ0-d9bJQ9T4yZf7gQ4QXWjNNRVGOJqW5vnmluFU9cmFLNbCdwPzW0MB6o72Srhbn2XiSBDK5S7kujt4hEIFDtoCc2wfbMgHi-MzuZVrLxkQU9iKG-NKocUaU5K3OSl3q7_qLeDXh1nJg4bzwKh6nHuKrkW38SdW54BYXyv8YPtKdQ_oVpZ8fxE2NymZR64YlnWveeYDCOd2dc0RWRNLmZM_31AqzEXakoYyb24hfipZ4K8ezIEvs0SqsWntJ4yUPBnkZrkHfaMwbmGkvsWXicJGLRAu-m8BGK5t2FrwP3BVxZpBYDW0Ajtp7gh9AeSEJQc1AoS1hWxxPgZwUb_A_APErsf-Ikf2fz3YU3OIPnhX6DCfAb47BP9_SO5bGljSByEqUhfNXykg3iBc2MBCwxaMG7wxIl9AIzO79SwTgH_00behRY90OIR3JIaZorJRJCaA6AXJIs8201nSTTArGKBkdtcO3ZFoqEZ4iUamt82H8E2eEXtsQcJA5gKUS0B-IhvNAFN5bnP4icIfBEYm-IW9RSW7ot0NQMyBvBB-nDMb2_UiZc6Mi9DFGmo-MVcQzbMacOJzAc0zoUGjSroH20Lte4UJ1nHNFMnjwYNcukoklBSdRYqzCexk_Ft8QMH9ZupmTrYMngLkT6Bz44YFvbb6-281l4SXqXVlcheLmD3h9TNe_8U3VkeoMDg_3kFzT7Yv4GaP.O0dzXNKPI8MRbK-JkITtLprIlaeV8IQQzfryGIP1Ba8`
	anonPacker := NewAnoncryptPacker(mock.ResolveEncPrivateKey)
	iden3BytesMsg, err := anonPacker.Unpack([]byte(jwe))
	require.NoError(t, err)
	actualMsgBytes, err := json.Marshal(iden3BytesMsg)

	require.NoError(t, err)
	require.JSONEq(t, string(msgBytes), string(actualMsgBytes))

}
