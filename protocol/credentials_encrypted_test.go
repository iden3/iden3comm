package protocol_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)

const encryptedCredentialIssuanceTemplate = `
{
  "id": "f0885dd0-e60e-11ee-b3e8-de17148ce1ce",
  "typ": "application/iden3comm-plain-json",
  "type": "https://iden3-communication.io/credentials/0.1/issuance",
  "thid": "f08860d2-e60e-11ee-b3e8-de17148ce1ce",
  "body": {
    "credential": {
      %s,
      "credentialStatus": {
          "id": "https://rhs-staging.polygonid.me/node?state=b4041204f0928400d68da969f2a6820a7b6071093483d4ce6d6237a17840451c",
          "revocationNonce": 1450732850,
          "statusIssuer": {
            "id": "https://issuer-node-core-api-testing.privado.id/v2/agent",
            "revocationNonce": 1450732850,
            "type": "Iden3commRevocationStatusV1.0"
          },
          "type": "Iden3ReverseSparseMerkleTreeProof"
        },
      "proof": [
          {
            "type": "BJJSignature2021",
            "issuerData": {
              "id": "did:iden3:polygon:amoy:xHV7UUYn7tx3KyzcyXTcnLjvAA9tJRVWCVGErQFRV",
              "state": {
                "claimsTreeRoot": "dd80f4cbef4290fdb5aa73ae95d9c65ea421b766a9d335ad1204255386851d1c",
                "value": "1d633c6d18e8101341f67da2d2e4448244d5e75f230080d8ae802781e8220d19"
              },
              "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f4223360d1687fa64ab33ee8ce4ed1c03cba411d6205e418b844be5cbe7be5041468649e0d60e2294f9f5e866b8670d198c0f3110b2f093317ba368e6264b91d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "mtp": {
                "existence": true,
                "siblings": []
              },
              "credentialStatus": {
                "id": "https://rhs-staging.polygonid.me/node?state=1d633c6d18e8101341f67da2d2e4448244d5e75f230080d8ae802781e8220d19",
                "revocationNonce": 0,
                "statusIssuer": {
                  "id": "https://issuer-node-core-api-testing.privado.id/v2/agent",
                  "revocationNonce": 0,
                  "type": "Iden3commRevocationStatusV1.0"
                },
                "type": "Iden3ReverseSparseMerkleTreeProof"
              }
            },
            "coreClaim": "7ed2bce3d6fab6efe706a7e76a0881dd2200000000000000000000000000000001b15b112b1036337c49e97a8f9abd452878bebed4a2c2fac91def928b550e00078e912f71bf9d3979a21d140bea8f2d5f620a8cacbf7e5e3b3d0f48ed6beb2d0000000000000000000000000000000000000000000000000000000000000000326d785600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "25c7962a5a11d906d490cc6cf522d332405326ec82f35ee5538301557a314628b452b4fca9292613cb2f9983c5ea6b0ea5411b793d3796b232abe84875c94001"
          }
        ]
    }
  },
  "from": "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE",
  "to": "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
}`

func TestEncryptedCredentialIssuanceMessage(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected string
		format   protocol.EncryptedPayloadFormat
	}{
		{
			name: "JWE JSON Serialization",
			payload: `"payload": {
          "ciphertext": "G94AlOo9R0Bz1L8ypk_Ls4KyjbxjsU2FK3X-HZifdkC9mcVP3wZ4zc2Lgca4jlLzHG4bG5LSS9spVhiZhZ0FFq6Lyo8PtEVAxvW8QmquvgHJ5kJqYK1Wuiry-_hzIdwJqBwc3SCIkTi15KON-LaBFW20dRS4QN8BFVQw6inbxb7gA3ULqLxU-iy6A2oHRiHTQ5A-8PrPvURtf6kxaP1JZ6ozmMSLfpZY7WezvFCgnokYa4eeIoDYYBduSxMnGdYbSZqq_wN-WujTxc1hVdyOYiz-YaZs6UiemzGl8_5F5i5B4Mx0Pf28kzTUzs3ivZtawtWPI8mxNdIuPRg4ivrz2EooIBba9eAEgMj_JdYFI9RQtf0LlCBlcIzdnsC_BwSZgpM5alqOUgRH7SECMB00oon73qlw0ZxLbqxSScXcStwHaJEcrrKw5ZzsM5IB7etqP4Wz9q95e8V3y79ms7l4m48HqbcXjQ",
          "encrypted_key": "aF0cMjVh4k2je1Y5neP-JD_Z4gSXkbfcVwq-S4f_4-5vCqY7kJAtQZYeyaLSVweU2inm5hvwYgf9dnn7q4wX_P1tPLAS5jYYSJd5-ev89av2vlGIPQApAshcKGrTM01Zg9Ewl19bCoTXsfU632AC4V3_Qj5-nkl3m7M-_7rVbvj8yeLtJaYDHdDnF7OORZrYnu-vYENArnhHuE4S9MsnByF2TSO_eZ0_aL8DljTvtvjo9G6J8tV5IbuRz6nOokVuRHoPlyq22ONACW7nHh1sGVd7gTeztsT2z9JAi5szdMe23rgbpTu3FbnG7yxAunQ5MnCLJ5OljGK1BDLpdPOrpw",
          "iv": "ZrFLdKgYqa1LrWIC",
          "protected": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGlkOmlkZW4zOmJpbGxpb25zOnRlc3Q6MlZ4bm9pTnFkTVB5SE10VXdBRXpobldxWEdrRWVKcEFwNG50VGtMOFhUI2tleTEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tZW5jcnlwdGVkLWpzb24ifQ",
          "tag": "rbUb5eW4Hgng-AMd-OPxeQ"
      }`,
			expected: `{
          "ciphertext": "G94AlOo9R0Bz1L8ypk_Ls4KyjbxjsU2FK3X-HZifdkC9mcVP3wZ4zc2Lgca4jlLzHG4bG5LSS9spVhiZhZ0FFq6Lyo8PtEVAxvW8QmquvgHJ5kJqYK1Wuiry-_hzIdwJqBwc3SCIkTi15KON-LaBFW20dRS4QN8BFVQw6inbxb7gA3ULqLxU-iy6A2oHRiHTQ5A-8PrPvURtf6kxaP1JZ6ozmMSLfpZY7WezvFCgnokYa4eeIoDYYBduSxMnGdYbSZqq_wN-WujTxc1hVdyOYiz-YaZs6UiemzGl8_5F5i5B4Mx0Pf28kzTUzs3ivZtawtWPI8mxNdIuPRg4ivrz2EooIBba9eAEgMj_JdYFI9RQtf0LlCBlcIzdnsC_BwSZgpM5alqOUgRH7SECMB00oon73qlw0ZxLbqxSScXcStwHaJEcrrKw5ZzsM5IB7etqP4Wz9q95e8V3y79ms7l4m48HqbcXjQ",
          "encrypted_key": "aF0cMjVh4k2je1Y5neP-JD_Z4gSXkbfcVwq-S4f_4-5vCqY7kJAtQZYeyaLSVweU2inm5hvwYgf9dnn7q4wX_P1tPLAS5jYYSJd5-ev89av2vlGIPQApAshcKGrTM01Zg9Ewl19bCoTXsfU632AC4V3_Qj5-nkl3m7M-_7rVbvj8yeLtJaYDHdDnF7OORZrYnu-vYENArnhHuE4S9MsnByF2TSO_eZ0_aL8DljTvtvjo9G6J8tV5IbuRz6nOokVuRHoPlyq22ONACW7nHh1sGVd7gTeztsT2z9JAi5szdMe23rgbpTu3FbnG7yxAunQ5MnCLJ5OljGK1BDLpdPOrpw",
          "iv": "ZrFLdKgYqa1LrWIC",
          "protected": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGlkOmlkZW4zOmJpbGxpb25zOnRlc3Q6MlZ4bm9pTnFkTVB5SE10VXdBRXpobldxWEdrRWVKcEFwNG50VGtMOFhUI2tleTEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tZW5jcnlwdGVkLWpzb24ifQ",
          "tag": "rbUb5eW4Hgng-AMd-OPxeQ"
      }`,
			format: protocol.EncryptedFormatJWEJSONSerialization,
		},
		{
			name:     "JWE String Serialization",
			payload:  `"payload": "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJraWQiOiJfOTF1OGtESTRVRUhmT2FGUHAyZGQyWUlsbGRpa1BWSzQybGR3T0FUQUpvIiwidHlwIjoiSldFIn0.H5dSdEDWjBOXRfrpDLcz_Mn4m7EAVKhzCRyfWCLHXOe4OhvIkV3KCMldkQL1wHJidQ8E7qOW1ImFaK36BJflyaVhCQd0o5RT.cT83StoZ09exRsLBh17LYg.y5Dnz7bt17nHKPDaUR3sT3KFuIepzHPOCcv09xnK3BzKu1gicsjbTBG16Hk9WilfX8nVt78Hw2NKhANGQ59W09fvtIYlVX2gSQHsJR6dfgXqxrPa7hUbV1qCHjgV1i6Slfcn7oXoh69fHvVUJfxD7TfcVFebs1iskP_6U2bzbak51TsUn-R0v-oF8VUajK3vjteVcgov7aqhSitZW6Hnbw.BVZ3Z6hVhRDKEZ0HBIafqkF5ZfYgMr3fZ1oqRfd1OvA"`,
			expected: "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJraWQiOiJfOTF1OGtESTRVRUhmT2FGUHAyZGQyWUlsbGRpa1BWSzQybGR3T0FUQUpvIiwidHlwIjoiSldFIn0.H5dSdEDWjBOXRfrpDLcz_Mn4m7EAVKhzCRyfWCLHXOe4OhvIkV3KCMldkQL1wHJidQ8E7qOW1ImFaK36BJflyaVhCQd0o5RT.cT83StoZ09exRsLBh17LYg.y5Dnz7bt17nHKPDaUR3sT3KFuIepzHPOCcv09xnK3BzKu1gicsjbTBG16Hk9WilfX8nVt78Hw2NKhANGQ59W09fvtIYlVX2gSQHsJR6dfgXqxrPa7hUbV1qCHjgV1i6Slfcn7oXoh69fHvVUJfxD7TfcVFebs1iskP_6U2bzbak51TsUn-R0v-oF8VUajK3vjteVcgov7aqhSitZW6Hnbw.BVZ3Z6hVhRDKEZ0HBIafqkF5ZfYgMr3fZ1oqRfd1OvA",
			format:   protocol.EncryptedFormatJWEStringSerialization,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			basicMessage := fmt.Sprintf(encryptedCredentialIssuanceTemplate, tt.payload)

			var message protocol.EncryptedCredentialIssuanceMessage
			err := json.Unmarshal([]byte(basicMessage), &message)
			require.NoError(t, err)
			require.NotEmpty(t, message.Body.Credential.Proof)            // check if proof is parsed correctly
			require.NotEmpty(t, message.Body.Credential.CredentialStatus) // check if credential status is parsed correctly

			require.Equal(t, tt.format, message.Body.Credential.Payload.Type())

			switch tt.format {
			case protocol.EncryptedFormatJWEJSONSerialization:
				var dst json.RawMessage // is posible to use JWT struct from go-jose and other libraries or map[string]interface{}
				err = message.Body.Credential.Payload.Get(&dst)
				require.NoError(t, err)
				require.JSONEq(t, tt.expected, string(dst))
			case protocol.EncryptedFormatJWEStringSerialization:
				var dst string
				err = message.Body.Credential.Payload.Get(&dst)
				require.NoError(t, err)
				require.Equal(t, tt.expected, dst)
			}

		})
	}
}
