package packers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2/mock"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func TestAnoncryptPacker_Pack(t *testing.T) {
	var msgBytes = []byte(`{"id":"123","type":"https://iden3-communication.io/authorization/1.0/response","from":"119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ","body":{"scope":[{"type":"zeroknowledge","circuitId":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)

	privKey, err := mock.ResolveEncPrivateKey(mock.MockRecipientKeyID)
	require.NoError(t, err)

	key, err := mock.ResolveKeyID(mock.MockRecipientKeyID)
	require.NoError(t, err)

	anonPacker := AnoncryptPacker{}
	ciphertext, err := anonPacker.Pack(msgBytes, AnoncryptPackerParams{
		RecipientKey: key,
	})
	require.NoError(t, err)
	require.NotEqual(t, 0, len(ciphertext))

	jweMessage, err := jwe.Parse(ciphertext)
	require.NoError(t, err)

	var actualTypeKey string
	err = jweMessage.ProtectedHeaders().Get(jwe.TypeKey, &actualTypeKey)
	require.NoError(t, err)
	require.Equal(t, string(MediaTypeEncryptedMessage), actualTypeKey)

	iden3BytesMsg, err := jwe.Decrypt(ciphertext,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), privKey))
	require.NoError(t, err)
	require.Equal(t, msgBytes, iden3BytesMsg)
}

func tryDecrypt(t *testing.T, alg jwa.KeyEncryptionAlgorithm,
	privKey interface{}, ciphertext []byte, source string) {
	decrypted, err := jwe.Decrypt(ciphertext, jwe.WithKey(alg, privKey))
	require.NoError(t, err)
	require.Equal(t, source, string(decrypted))
}

func TestAnoncryptPacker_Pack_MultiRecipients(t *testing.T) {
	aliceRSA := mock.NewMockRSA(t, mock.AliceDigest)
	bobRSA := mock.NewMockRSA(t, mock.BobDigest)
	viktorRSA := mock.NewMockRSA(t, mock.ViktorDigest)

	aliceEC := mock.NewMockEC(t, mock.AliceDigest)
	bobEC := mock.NewMockEC(t, mock.BobDigest)
	viktorEC := mock.NewMockEC(t, mock.ViktorDigest)

	tests := []struct {
		name                        string
		didDocumentResolverFuncMock DidDocumentResolverFunc
		message                     []byte
		recipients                  []struct {
			did     string
			privKey interface{}
			alg     jwa.KeyEncryptionAlgorithm
		}
	}{
		{
			name: "pack message with 3 recipients. All with RSA keys",
			didDocumentResolverFuncMock: func(_ context.Context, did string, _ *services.ResolverOpts) (
				*document.DidResolution, error,
			) {
				switch did {
				case "did:example:alice":
					return aliceRSA.BuildDidDocWithRSAKey(t, "did:example:alice"), nil
				case "did:example:bob":
					return bobRSA.BuildDidDocWithRSAKey(t, "did:example:bob"), nil
				case "did:example:viktor":
					return viktorRSA.BuildDidDocWithRSAKey(t, "did:example:viktor"), nil
				}
				return nil, nil
			},
			message: []byte("Go go Gophers!"),
			recipients: []struct {
				did     string
				privKey interface{}
				alg     jwa.KeyEncryptionAlgorithm
			}{
				{"did:example:alice", aliceRSA.PrivateKey, jwa.RSA_OAEP_256()},
				{"did:example:bob", bobRSA.PrivateKey, jwa.RSA_OAEP_256()},
				{"did:example:viktor", viktorRSA.PrivateKey, jwa.RSA_OAEP_256()},
			},
		},
		{
			name: "pack message with 3 recipients. All with EC keys",
			didDocumentResolverFuncMock: func(_ context.Context, did string, _ *services.ResolverOpts) (
				*document.DidResolution, error) {
				switch did {
				case "did:example:alice":
					return aliceEC.BuildDidDocWithECKey(t, "did:example:alice"), nil
				case "did:example:bob":
					return bobEC.BuildDidDocWithECKey(t, "did:example:bob"), nil
				case "did:example:viktor":
					return viktorEC.BuildDidDocWithECKey(t, "did:example:viktor"), nil
				}
				return nil, nil
			},
			message: []byte("Go go Gophers!"),
			recipients: []struct {
				did     string
				privKey interface{}
				alg     jwa.KeyEncryptionAlgorithm
			}{
				{"did:example:alice", aliceEC.PrivateKey, jwa.ECDH_ES_A256KW()},
				{"did:example:bob", bobEC.PrivateKey, jwa.ECDH_ES_A256KW()},
				{"did:example:viktor", viktorEC.PrivateKey, jwa.ECDH_ES_A256KW()},
			},
		},
		{
			name: "pack message with 2 recipients. One with RSA key, another with EC key",
			didDocumentResolverFuncMock: func(_ context.Context, did string, _ *services.ResolverOpts) (
				*document.DidResolution, error) {
				switch did {
				case "did:example:alice":
					return aliceRSA.BuildDidDocWithRSAKey(t, "did:example:alice"), nil
				case "did:example:bob":
					return bobEC.BuildDidDocWithECKey(t, "did:example:bob"), nil
				}
				return nil, nil
			},
			message: []byte("Go go Gophers!"),
			recipients: []struct {
				did     string
				privKey interface{}
				alg     jwa.KeyEncryptionAlgorithm
			}{
				{"did:example:alice", aliceRSA.PrivateKey, jwa.RSA_OAEP_256()},
				{"did:example:bob", bobEC.PrivateKey, jwa.ECDH_ES_A256KW()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anonPacker := NewAnoncryptPacker(nil, tt.didDocumentResolverFuncMock)
			var recipientsDids []AnoncryptRecipients
			for _, r := range tt.recipients {
				recipientsDids = append(recipientsDids, AnoncryptRecipients{DID: r.did, JWKAlg: r.alg.String()})
			}
			ciphertext, err := anonPacker.Pack(tt.message, AnoncryptPackerParams{
				Recipients: recipientsDids,
			})
			require.NoError(t, err)

			for _, r := range tt.recipients {
				tryDecrypt(t, r.alg, r.privKey, ciphertext, string(tt.message))
			}
		})
	}
}

func TestAnoncryptPacker_Unpack_JS_Aligen(t *testing.T) {
	const (
		originMessage = `{"id":"8589c266-f5f4-4a80-8fc8-c1ad4de3e3b4","thid":"43246acb-b772-414e-9c90-f36b37261000","typ":"application/iden3comm-encrypted-json","type":"https://iden3-communication.io/passport/0.1/verification-request","from":"did:iden3:polygon:amoy:x6x5sor7zpxUwajVSoHGg8aAhoHNoAW1xFDTPCF49","to":"did:iden3:billions:test:2VxnoiNqdMPyHMtUwAEzhnWqXGkEeJpAp4ntTkL8XT"}`

		jsJWE = `{"ciphertext":"fgMb1WEQQTf4-vndsQ5NsV-cl9zqgqZavNV93HWTKl7rRCp_S1bFHZ1EUSq5mOlsT6zB5k8frF4nrBgppiqD2ktrQiymDcIACMEm281HZZgRi0r-qNJpQBzXWfLiWaMEEr8ZDD-mjldeKtXGtazPNOunXFBEqCaEhSjcdr7jqFHgWuEuJDzBOqAnQUhGbTPYbnuFDpMOJXL8znfhfCU3jJz1wvrbdR9mz9sE2YonUXFGag-nekcFdcqPmZyjNJGzvMwYHqYpKZAvC3QQlaS1r98uMg0CMadtLh8PQQzlQaXgq8HW6rdFonNurZELDQ_H_n9t-tBCy_gJwzrnXhq4iNjXDBbPEqRVnuWmDIkThJ8EifwMZsDGXGp-LMWfAn-L5qsVykvXdfK6PU1Q-j0IUpiBdtDo_j6oXERIraT8kU-c21Ww1DmZf9ubz4wJg_Fvy68rSJDuwehQzl9tU-K-V7UbG1ybmA","iv":"_2dk0yGlVcGm-nUi","recipients":[{"encrypted_key":"cSznwhjoVAuexmVtnlWIgJJSKviKJld-lfhqLpsEoWYHwszzWu2jr6gb8T5Hs18u8FLmv5_oKRftFCrD0DjtUJVdjMjS7-76Lf2NLyFyR5hfTQKPJ5tifJHRZhDPmD3Rwxqe2AJjuabfL7K7_qPwwLmbClAovOxokSYxpDnFZvJI0W0fbumt2S_7j7nufveWPITx4VoUD__k6T--uljd6uTmbFfi85V5gkWthf03G6MYV-a5UdpeNIcCakQBbx3IPeoRi9gAV48CLEHOpxSG8laAYKENwWZyjMfT7CNhIKVJR5iBcq6LCp-_aDfKZ6sFVsbIuRUh7Qobxrk-lal4vg","header":{"alg":"RSA-OAEP-256","kid":"did:iden3:billions:test:2VxnoiNqdMPyHMtUwAEzhnWqXGkEeJpAp4ntTkL8XT#key1"}},{"encrypted_key":"AyoRNE0e8cbj4vM8L0b6EKZfq-l7lwMwk10q9z9FWcnOjx--rwLAyGSvmS_4_rjjKjtqf1tp7xyH_CqFP2UVx9mnmgyKC6cbCWAuvKtP3eV7GtmKsIBD-f0hMzNAo6h-qhOlyUOIWFUadA8Q3Uf7O6Trfy3yq9V25d13fBTTuN0ta391VPJba9qqw4erfrdWpnlIhoHApCYfW6mejijvQ03lDlOVuY38mTrYgxbA0X_hA_2qPGRzTjchsElWDFeQyzLfAVvCVrrbMDoatM9L6OFP08mK1ltVguMKV0C4IFQGKhXhPAkRz6smBB0OI6CZcyKvQjPekqU6PgRy8mShEA","header":{"alg":"RSA-OAEP-256","kid":"did:iden3:polygon:amoy:A6x5sor7zpxUwajVSoHGg8aAhoHNoAW1xFDTPCF49#key1"}}],"tag":"1jZdSruJ8l_3cC2CoY6vtA","protected":"eyJlbmMiOiJBMjU2R0NNIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLWVuY3J5cHRlZC1qc29uIn0"}`

		endUserDID = "did:iden3:billions:test:2VxnoiNqdMPyHMtUwAEzhnWqXGkEeJpAp4ntTkL8XT"
		endUserJWK = `{
			"kty": "RSA",
			"n": "oJ_RM4-dKCwAm_iXCDBzSABwOr5eOCrTVzlLikx0dK1BoO8ilHr9Yx7F3F5Q5exZ6g_lz_5YKSQ31ZNWjAjLOZnRvLkXGA2p_lfFNGGDsW7Xw2OvVy-kX7Y-O1Yn6rGW-ZMCslcc4hdHQbrBa3MdwLFDfAMcHDfZYWOVhU3brGIr0cmXRfZ6U-1hPT-3K_rwCknbiir8GivoLXinIad95JNwyIUytfBc-New_PrcUYoDQH6GI6bu8m2_ya3QuGIR-Lgn5HGcXtd9Lw9qnMc31EcJMKyG1KxMAVUFcoyADDskRCDfd-PWr50Upx_F9V3PE9e7ZOrXRn_hQF0XYG-MGQ",
			"e": "AQAB",
			"d": "CLsjNaKp8-Hvbwr8V7Q9gfWPJCxOpg4y4ngBco0tG94Clh9FkY1dambE8dF5I4RdT1cpomyUiXj35X6-qro8JL-HGnNzrUmp2sLV2_7seAe6x_rKUEqNTGwVNie83_mjB6IteHj6f5ItHAYtJxxw6rVgAhTPsXt6MBxoB2DX7ubpmLPzqyTjE_teVjyrj9i9JZ-W1kRMbLWuALviZbrrtEHdEBKaRvtaeWcf5MHuGHw2RCTHhoHzty8NHasdwSsu0t1dL-88ulxDgK9EdYOHZ17dkmNrrUCq0wpa1_InbV_JC9BoN6Fw7_22M67Suq2v9JUg_K4kid45Vumvn_Mq4Q",
			"p": "2kgLhksExewH6ukrXwIMRdKNGRZwWDfprtxjiXW6qg_Qtlo-NX1NUZCilbKAqhYpPdEq2UFElhcF7e1cDkZkhYUQKcOnn_80vWPfoVD8LykDaaNA_E7p1sc78hfm3pKq6AJ26X_qRvV2x0nyFT6S5WykvlRIWRxvr66Y25y192E",
			"q": "vGE8VBMc4L7IExssUN5bSPidzH8FB9yJw--i8cYGLns-Exqy3XO78GCgvB4yKjmz_M5aMZM9FFqJmbPYI2u3STQNvuv8Fss7YqMYWVLWIi2lzx_5e2_coNB7zfn7yyu9R900Nl9WUlWz2Qtu9yXX-RfT_aBr7wg0z3oIP5BAJ7k",
			"dp": "j-vOxXXzKLiuo8GnmhYUl3jzFWaJHnGHP4cKjhi0wep5l7I6sDP05eGygXdXhE3mVV7znJl_KmL1wuGsv7DEGJEajh72B_VSBcmzKn7mOAYXvPAqKfGyFq34pXADBh-4Vg9B7kUr6CtybIYh-sXuPxz6JpAVv8OTFEfPe4WBKSE",
			"dq": "V3Zd6DsngUGS6ywGm1Vh1LN5sGSZFVlTrWEpqk9it1oJLB2NRjxh2e1DM5RhfjFkW9ADGFlgVn7ivDY_99IfOyGr8CTo2jxpyhYnS_Gl8iB3h380-hapvRCPKscSHPal3yPZBhWlonygD_m6_4zWhZSGnI9LDaQlwN7LzZdP8iE",
			"qi": "rOj_Zb2hTI1Q-K93QDYEvcyaiE266_MbEhqYWOWOik5J2XAmIcb7ns1rNVfJyLXEeu584SZcs0LCwxTZB-nKKcyTbTqKZP9QanjXGZn6jZprt0J5s4PmZPonAFuM8DgpPUJQwKUTlxVPdSm_TtgxC7hbRrhzjGFduROXu_iltZU",
			"alg": "RSA-OAEP-256"
		}`

		anotherUserDID = "did:iden3:polygon:amoy:A6x5sor7zpxUwajVSoHGg8aAhoHNoAW1xFDTPCF49"
		anotherJWK     = `{
			"kty": "RSA",
			"alg": "RSA-OAEP-256"
			"n": "qXiO4kdzR5-1iVfQftDVcJi5VcjixNJOAhZEDPot4GMJFuKAe_Oq-7mVd7hHot6T_8IstXfTSijsWq8S1CQg8Ov9Aqv92UQUX-R0QbwzplkbrzfEUEWZAR46T9BqWJ1WvCMqBL54zD9ppB_suE4qBvXsosMxPEkzAEmmGpNPi5GlNLWxtDMiR-u5rs7Tje8V1k-uE8cXORsrBNUQ--Iq71Vpbp5YJtDveDMk5nDuZFkscXI2VHc2sloStZ9DsfMS47jItkbDm5GyFlIdvFSrABVM5gyrDM7SOUzG5ZeiCcKm50wgYIm8QizIHZqHVmexFtcFl8VFHcDVtfIkbXYx5w",
			"e": "AQAB",
			"d": "GsSLkQsnFr-PrXdc28MBi4zb7URTKTJsluDMc95KQ8BwzZgOIkXtEmCQTr4hNoUAjGuvoyQfj_2hw3sWtsJUH6mup27iJCCgNTtA76cZ42L8v_LHg8RSc_5ByJyLR57mdcX6G5C4RM6ZUY6nVb8m3T2X2GeLTdHkB94aKeVtsYYYbIOOGDtfDTD_Z-dZ3gdVH2psc2fZstmdg_okaPCzzVD49aWevnB8Y9BzUhwNV6oD_xyJwxGjT1NOXcZV6HMzBBjJ44eCBegus0rjezXrFNB0nPuJRkwt5bfrZmzVfQbYUyIwWrF6vQpjYr6mqQtsdm_U_hykQdx482FMk-WJfQ",
			"p": "0dt_krUkUEVD2QkYwhxiM0xwPUiK3hiL5aSkYo5Z3NPpzi7FbrY-a3rSxmTcMXC4rqx1LzoKmKeaDPjnjpUiWqys1588bGc8EPxMVtfiYO60q-aB4PSFGKNEFP4z_12LMsyPao-bctx1DUki07Rdi3oOd8td13wLtfYyLzV7sHU",
			"q": "zrvGtN6mLXzcg7MI4nVKxqYHEACI7EJYrmehVSK09nkuGCYgGhiP-PiR_O39wh1zN73HTatvcIz91QQC4mMvFJoGF-J3J4zqMkiv7gnkJ5mRj3c125iRPclhJDNhgr-yOHEu2upFg31CGZhCfvOi9TScQCU4l20vqDEoobXnjWs",
			"dp": "jr6BHid8leUna1-WqaJo4X_i8KyBWOTVc9Tzw94UHfM_G_IQdWgdOTqIWE6OwEpuNNI1u3P9dSy7yosb5o5mmcrOnrQ_g3UNFHio7IFYCJsV5b-bJIruZX3Yd3cZo1_bqSgffVpFYHG4ZNsUh3AuGQti__Ui1coYpSLbq-TzR2k",
			"dq": "FZum30zOTb7ZRaK28QSVdkHwRwnnRdqBbmlCgaWJCKIN4VRK0q9yjPFeQPOXLGzrmA3sAQBEO51hApzSuFrpltuqe2CeV7Hw4KScTuMVx9XTUw2AwZ0mwTCFSMVeEc57kE60OQl3jpDPEeHKQX6xr7N6CXJagelVq9zHhG-A7lU",
			"qi": "CvIzm858pE_4gW_yr7mUfl6Qo7jacUzim2sFM1kObBg_sNDLW-P8L2zGjmDJxUCHeYG6Gdj-219MN1-qQQnBhpg5LLENkFoseumv_2A8i0uP_j2MMlNFed7P0yGwwfZwcjAmieN2ULfbxJ1Vs7XYg6bzPoM7Sb0JyZRAQfcBtLk",
		}`
	)

	privateKeyResolverFunc := func(keyID string) (key interface{}, err error) {
		switch keyID {
		case endUserDID + "#key1":
			k, err := jwk.ParseKey([]byte(endUserJWK))
			require.NoError(t, err)
			return k, nil
		case anotherUserDID + "#key1":
			k, err := jwk.ParseKey([]byte(anotherJWK))
			require.NoError(t, err)
			return k, nil
		default:
			require.FailNow(t, "unexpected key id: "+keyID)
			return nil, nil
		}
	}

	packer := NewAnoncryptPacker(privateKeyResolverFunc, nil)
	decryptedMsg, err := packer.Unpack([]byte(jsJWE))
	require.NoError(t, err)

	decryptedMsgBytes, err := json.Marshal(decryptedMsg)
	require.NoError(t, err)

	require.JSONEq(t, originMessage, string(decryptedMsgBytes))
}

func TestAnoncryptPacker_GetSupportedProfiles(t *testing.T) {
	packer := AnoncryptPacker{}
	profiles := packer.GetSupportedProfiles()
	expected := []string{
		"iden3comm/v1;env=application/iden3comm-encrypted-json;alg=RSA-OAEP-256,ECDH-ES+A256KW",
	}
	require.ElementsMatch(t, expected, profiles)
}

func TestDecryptForListBigListOfRecipients(t *testing.T) {
	var (
		aliceDID  = "did:example:alice"
		bobDID    = "did:example:bob"
		viktorDID = "did:example:viktor"
	)

	recipients := map[string]struct {
		privateJWK map[string]interface{}
		doc        document.DidResolution
	}{}
	for _, r := range []string{aliceDID, bobDID, viktorDID} {
		rsaKey := mock.NewMockRSA(t, rand.Reader)
		ecKey := mock.NewMockEC(t, rand.Reader)

		comm := mock.NewCommonMock(rsaKey, ecKey)

		recipients[r] = struct {
			privateJWK map[string]interface{}
			doc        document.DidResolution
		}{
			privateJWK: rsaKey.GetJWKForPrivateKey(t),
			doc:        *comm.BuildDidDocWithAllKeys(t, r),
		}
	}

	didDocumentResolverFunc := func(_ context.Context, did string, _ *services.ResolverOpts) (
		*document.DidResolution, error,
	) {
		if doc, ok := recipients[did]; ok {
			return &doc.doc, nil
		}
		return nil, fmt.Errorf("not found")
	}

	// try to decryupt only with viktor's RSA key
	privateKeyResolverFunc := func(keyID string) (key interface{}, err error) {
		if keyID == viktorDID+"#rsa-key-1" {
			b, err := json.Marshal(recipients[viktorDID].privateJWK)
			require.NoError(t, err)
			return jwk.ParseKey(b)
		}
		return nil, fmt.Errorf("not found")
	}

	anonPacker := NewAnoncryptPacker(privateKeyResolverFunc, didDocumentResolverFunc)

	originMessage := `{"id":"8589c266-f5f4-4a80-8fc8-c1ad4de3e3b4","thid":"43246acb-b772-414e-9c90-f36b37261000","typ":"application/iden3comm-encrypted-json","type":"https://iden3-communication.io/passport/0.1/verification-request","from":"did:iden3:polygon:amoy:x6x5sor7zpxUwajVSoHGg8aAhoHNoAW1xFDTPCF49","to":"did:iden3:billions:test:2VxnoiNqdMPyHMtUwAEzhnWqXGkEeJpAp4ntTkL8XT"}`

	ciphertext, err := anonPacker.Pack([]byte(originMessage), AnoncryptPackerParams{
		Recipients: []AnoncryptRecipients{
			{DID: aliceDID, JWKAlg: jwa.RSA_OAEP_256().String()},
			{DID: bobDID, JWKAlg: jwa.ECDH_ES_A256KW().String()},
			{DID: viktorDID, JWKAlg: jwa.RSA_OAEP_256().String()},
		},
	})
	require.NoError(t, err)

	decryptedMsg, err := anonPacker.Unpack(ciphertext)
	require.NoError(t, err)

	decryptedBytes, err := json.Marshal(decryptedMsg)
	require.NoError(t, err)

	require.JSONEq(t, string(decryptedBytes), originMessage)
}

func TestAnoncryptPacker_Pack_JS_Aligen(t *testing.T) {
	t.Skipf("This test is used to generate a JWE token for testing in JS")
	const (
		originMessage = `{"id":"8589c266-f5f4-4a80-8fc8-c1ad4de3e3b4","thid":"43246acb-b772-414e-9c90-f36b37261000","typ":"application/iden3comm-encrypted-json","type":"https://iden3-communication.io/passport/0.1/verification-request","from":"did:iden3:polygon:amoy:x6x5sor7zpxUwajVSoHGg8aAhoHNoAW1xFDTPCF49","to":"did:iden3:billions:test:2VxnoiNqdMPyHMtUwAEzhnWqXGkEeJpAp4ntTkL8XT"}`

		endUserDID = "did:iden3:billions:test:2VxnoiNqdMPyHMtUwAEzhnWqXGkEeJpAp4ntTkL8XT"
		endUserJWK = `{
			"kty": "RSA",
			"n": "oJ_RM4-dKCwAm_iXCDBzSABwOr5eOCrTVzlLikx0dK1BoO8ilHr9Yx7F3F5Q5exZ6g_lz_5YKSQ31ZNWjAjLOZnRvLkXGA2p_lfFNGGDsW7Xw2OvVy-kX7Y-O1Yn6rGW-ZMCslcc4hdHQbrBa3MdwLFDfAMcHDfZYWOVhU3brGIr0cmXRfZ6U-1hPT-3K_rwCknbiir8GivoLXinIad95JNwyIUytfBc-New_PrcUYoDQH6GI6bu8m2_ya3QuGIR-Lgn5HGcXtd9Lw9qnMc31EcJMKyG1KxMAVUFcoyADDskRCDfd-PWr50Upx_F9V3PE9e7ZOrXRn_hQF0XYG-MGQ",
			"e": "AQAB",
			"d": "CLsjNaKp8-Hvbwr8V7Q9gfWPJCxOpg4y4ngBco0tG94Clh9FkY1dambE8dF5I4RdT1cpomyUiXj35X6-qro8JL-HGnNzrUmp2sLV2_7seAe6x_rKUEqNTGwVNie83_mjB6IteHj6f5ItHAYtJxxw6rVgAhTPsXt6MBxoB2DX7ubpmLPzqyTjE_teVjyrj9i9JZ-W1kRMbLWuALviZbrrtEHdEBKaRvtaeWcf5MHuGHw2RCTHhoHzty8NHasdwSsu0t1dL-88ulxDgK9EdYOHZ17dkmNrrUCq0wpa1_InbV_JC9BoN6Fw7_22M67Suq2v9JUg_K4kid45Vumvn_Mq4Q",
			"p": "2kgLhksExewH6ukrXwIMRdKNGRZwWDfprtxjiXW6qg_Qtlo-NX1NUZCilbKAqhYpPdEq2UFElhcF7e1cDkZkhYUQKcOnn_80vWPfoVD8LykDaaNA_E7p1sc78hfm3pKq6AJ26X_qRvV2x0nyFT6S5WykvlRIWRxvr66Y25y192E",
			"q": "vGE8VBMc4L7IExssUN5bSPidzH8FB9yJw--i8cYGLns-Exqy3XO78GCgvB4yKjmz_M5aMZM9FFqJmbPYI2u3STQNvuv8Fss7YqMYWVLWIi2lzx_5e2_coNB7zfn7yyu9R900Nl9WUlWz2Qtu9yXX-RfT_aBr7wg0z3oIP5BAJ7k",
			"dp": "j-vOxXXzKLiuo8GnmhYUl3jzFWaJHnGHP4cKjhi0wep5l7I6sDP05eGygXdXhE3mVV7znJl_KmL1wuGsv7DEGJEajh72B_VSBcmzKn7mOAYXvPAqKfGyFq34pXADBh-4Vg9B7kUr6CtybIYh-sXuPxz6JpAVv8OTFEfPe4WBKSE",
			"dq": "V3Zd6DsngUGS6ywGm1Vh1LN5sGSZFVlTrWEpqk9it1oJLB2NRjxh2e1DM5RhfjFkW9ADGFlgVn7ivDY_99IfOyGr8CTo2jxpyhYnS_Gl8iB3h380-hapvRCPKscSHPal3yPZBhWlonygD_m6_4zWhZSGnI9LDaQlwN7LzZdP8iE",
			"qi": "rOj_Zb2hTI1Q-K93QDYEvcyaiE266_MbEhqYWOWOik5J2XAmIcb7ns1rNVfJyLXEeu584SZcs0LCwxTZB-nKKcyTbTqKZP9QanjXGZn6jZprt0J5s4PmZPonAFuM8DgpPUJQwKUTlxVPdSm_TtgxC7hbRrhzjGFduROXu_iltZU",
			"alg": "RSA-OAEP-256"
		}`

		anotherUserDID = "did:iden3:polygon:amoy:A6x5sor7zpxUwajVSoHGg8aAhoHNoAW1xFDTPCF49"
		anotherJWK     = `{
			"kty": "RSA",
			"alg": "RSA-OAEP-256",
			"n": "qXiO4kdzR5-1iVfQftDVcJi5VcjixNJOAhZEDPot4GMJFuKAe_Oq-7mVd7hHot6T_8IstXfTSijsWq8S1CQg8Ov9Aqv92UQUX-R0QbwzplkbrzfEUEWZAR46T9BqWJ1WvCMqBL54zD9ppB_suE4qBvXsosMxPEkzAEmmGpNPi5GlNLWxtDMiR-u5rs7Tje8V1k-uE8cXORsrBNUQ--Iq71Vpbp5YJtDveDMk5nDuZFkscXI2VHc2sloStZ9DsfMS47jItkbDm5GyFlIdvFSrABVM5gyrDM7SOUzG5ZeiCcKm50wgYIm8QizIHZqHVmexFtcFl8VFHcDVtfIkbXYx5w",
			"e": "AQAB",
			"d": "GsSLkQsnFr-PrXdc28MBi4zb7URTKTJsluDMc95KQ8BwzZgOIkXtEmCQTr4hNoUAjGuvoyQfj_2hw3sWtsJUH6mup27iJCCgNTtA76cZ42L8v_LHg8RSc_5ByJyLR57mdcX6G5C4RM6ZUY6nVb8m3T2X2GeLTdHkB94aKeVtsYYYbIOOGDtfDTD_Z-dZ3gdVH2psc2fZstmdg_okaPCzzVD49aWevnB8Y9BzUhwNV6oD_xyJwxGjT1NOXcZV6HMzBBjJ44eCBegus0rjezXrFNB0nPuJRkwt5bfrZmzVfQbYUyIwWrF6vQpjYr6mqQtsdm_U_hykQdx482FMk-WJfQ",
			"p": "0dt_krUkUEVD2QkYwhxiM0xwPUiK3hiL5aSkYo5Z3NPpzi7FbrY-a3rSxmTcMXC4rqx1LzoKmKeaDPjnjpUiWqys1588bGc8EPxMVtfiYO60q-aB4PSFGKNEFP4z_12LMsyPao-bctx1DUki07Rdi3oOd8td13wLtfYyLzV7sHU",
			"q": "zrvGtN6mLXzcg7MI4nVKxqYHEACI7EJYrmehVSK09nkuGCYgGhiP-PiR_O39wh1zN73HTatvcIz91QQC4mMvFJoGF-J3J4zqMkiv7gnkJ5mRj3c125iRPclhJDNhgr-yOHEu2upFg31CGZhCfvOi9TScQCU4l20vqDEoobXnjWs",
			"dp": "jr6BHid8leUna1-WqaJo4X_i8KyBWOTVc9Tzw94UHfM_G_IQdWgdOTqIWE6OwEpuNNI1u3P9dSy7yosb5o5mmcrOnrQ_g3UNFHio7IFYCJsV5b-bJIruZX3Yd3cZo1_bqSgffVpFYHG4ZNsUh3AuGQti__Ui1coYpSLbq-TzR2k",
			"dq": "FZum30zOTb7ZRaK28QSVdkHwRwnnRdqBbmlCgaWJCKIN4VRK0q9yjPFeQPOXLGzrmA3sAQBEO51hApzSuFrpltuqe2CeV7Hw4KScTuMVx9XTUw2AwZ0mwTCFSMVeEc57kE60OQl3jpDPEeHKQX6xr7N6CXJagelVq9zHhG-A7lU",
			"qi": "CvIzm858pE_4gW_yr7mUfl6Qo7jacUzim2sFM1kObBg_sNDLW-P8L2zGjmDJxUCHeYG6Gdj-219MN1-qQQnBhpg5LLENkFoseumv_2A8i0uP_j2MMlNFed7P0yGwwfZwcjAmieN2ULfbxJ1Vs7XYg6bzPoM7Sb0JyZRAQfcBtLk"
		}`
	)

	didDocResolverFunc := func(_ context.Context, did string, _ *services.ResolverOpts) (*document.DidResolution, error) {
		switch did {
		case endUserDID:
			var kmap map[string]interface{}
			err := json.Unmarshal([]byte(endUserJWK), &kmap)
			require.NoError(t, err)

			return &document.DidResolution{
				DidDocument: &verifiable.DIDDocument{
					ID: endUserDID,
					VerificationMethod: []verifiable.CommonVerificationMethod{
						{
							ID:           endUserDID + "#key1",
							Type:         "JsonWebKey2020",
							Controller:   endUserDID,
							PublicKeyJwk: kmap,
						},
					},
				},
			}, nil
		case anotherUserDID:
			var kmap map[string]interface{}
			err := json.Unmarshal([]byte(anotherJWK), &kmap)
			require.NoError(t, err)

			return &document.DidResolution{
				DidDocument: &verifiable.DIDDocument{
					ID: anotherUserDID,
					VerificationMethod: []verifiable.CommonVerificationMethod{
						{
							ID:           anotherUserDID + "#key1",
							Type:         "JsonWebKey2020",
							Controller:   anotherUserDID,
							PublicKeyJwk: kmap,
						},
					},
				},
			}, nil
		default:
			require.FailNow(t, "unexpected did: "+did)
		}
		return nil, nil
	}

	packer := NewAnoncryptPacker(nil, didDocResolverFunc)
	ciphertext, err := packer.Pack([]byte(originMessage), AnoncryptPackerParams{
		Recipients: []AnoncryptRecipients{
			{DID: endUserDID},
			{DID: anotherUserDID},
		},
	})
	require.NoError(t, err)
	fmt.Printf("%s\n", ciphertext)
}
