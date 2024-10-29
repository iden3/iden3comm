package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaymentRequestMessagePaymentTypeUnmarshall(t *testing.T) {
	const paymentRequestTypeIden3PaymentRequestCryptoV1 = `
 {
  "id": "36f9e851-d713-4b50-8f8d-8a9382f138ca",
  "thid": "36f9e851-d713-4b50-8f8d-8a9382f138ca",
  "typ": "application/iden3comm-plain-json",
  "type": "https://iden3-communication.io/credentials/0.1/payment-request",
  "body": {
	 "agent": "<issuer-agent-url>", 
	 "payments": [
	  {
		 "credentials": [
		  {
		   "type": "AML",
		   "context": "<context_url>"
		  }
		 ],
		 "data": {
			 "type":"Iden3PaymentRequestCryptoV1",
			 "amount":"10", 
			 "id": "ox",
			 "chainId": "80002", 
			 "address": "0xpay1",
			 "currency": "ETH",
			 "expiration": "<timestamp>"
		 },
		"description":"you can pass the verification on our KYC provider by following the next link"
		}
	  ]
  },
  "to": "did:polygonid:polygon:mumbai:2qJUZDSCFtpR8QvHyBC4eFm6ab9sJo5rqPbcaeyGC4",
  "from": "did:iden3:polygon:mumbai:x3HstHLj2rTp6HHXk2WczYP7w3rpCsRbwCMeaQ2H2"
}
`

	const paymentRequestTypeIden3PaymentRailsRequestV1 = `
{
    "id": "b79b037c-0a6f-4031-a343-46e52e5f606b",
    "thid": "b79b037c-0a6f-4031-a343-46e52e5f606b",
    "from": "did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX",
    "to": "did:iden3:polygon:amoy:x7Z95VkUuyo6mqraJw2VGwCfqTzdqhM1RVjRHzcpK",
    "typ": "application/iden3comm-plain-json",
    "type": "https://iden3-communication.io/credentials/0.1/payment-request",
    "body": {
        "agent": "",
        "payments": [
            {
                "data": [
                    {
                        "type": "Iden3PaymentRailsRequestV1",
                        "@context": "https://schema.iden3.io/core/jsonld/payment.jsonld#Iden3PaymentRailsRequestV1",
                        "recipient": "0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a",
                        "amount": "30001",
                        "currency": "ETHWEI",
                        "expirationDate": "2024-10-14T13:22:31.956Z",
                        "nonce": "18",
                        "metadata": "0x",
                        "proof": [
                            {
                                "type": "EthereumEip712Signature2021",
                                "proofPurpose": "assertionMethod",
                                "proofValue": "0xd881e175b548b940406e8ed97e0fe58134ac93e381cb53c35f940040b1d890540cc9f4c0f3bf42b35d3dc72d29b203af5cbae968fafc1342332f63c3581a8e691b",
                                "verificationMethod": "did:pkh:eip155:80002:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
                                "created": "2024-10-14T12:22:31.964Z",
                                "eip712": {
                                    "types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
                                    "primaryType": "Iden3PaymentRailsRequestV1",
                                    "domain": {
                                        "name": "MCPayment",
                                        "version": "1.0.0",
                                        "chainId": "80002",
                                        "verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
                                        "salt": ""
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "type": "Iden3PaymentRailsRequestV1",
                        "@context": [
                            "https://schema.iden3.io/core/jsonld/payment.jsonld#Iden3PaymentRailsRequestV1",
                            "https://w3id.org/security/suites/eip712sig-2021/v1"
                        ],
                        "recipient": "0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a",
                        "amount": "60002",
                        "currency": "ETHWEI",
                        "expirationDate": "2024-10-14T13:22:31.956Z",
                        "nonce": "18",
                        "metadata": "0x",
                        "proof": [
                            {
                                "type": "EthereumEip712Signature2021",
                                "proofPurpose": "assertionMethod",
                                "proofValue": "0xd3606f34447c437ef7c13a1e407ad75597ee0229590de286e5775d1f1335ff93601d7a6398d69a4a3e2ddb4da5e30e61ef388d2ad6e0b50041731eaf3afe41ad1b",
                                "verificationMethod": "did:pkh:eip155:1101:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
                                "created": "2024-10-14T12:22:31.967Z",
                                "eip712": {
                                    "types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
                                    "primaryType": "Iden3PaymentRailsRequestV1",
                                    "domain": {
                                        "name": "MCPayment",
                                        "version": "1.0.0",
                                        "chainId": "1101",
                                        "verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
                                        "salt": ""
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "type": "Iden3PaymentRailsRequestV1",
                        "@context": [
                            "https://schema.iden3.io/core/jsonld/payment.jsonld#Iden3PaymentRailsRequestV1",
                            "https://w3id.org/security/suites/eip712sig-2021/v1"
                        ],
                        "recipient": "0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a",
                        "amount": "90003",
                        "currency": "ETHWEI",
                        "expirationDate": "2024-10-14T13:22:31.956Z",
                        "nonce": "18",
                        "metadata": "0x",
                        "proof": [
                            {
                                "type": "EthereumEip712Signature2021",
                                "proofPurpose": "assertionMethod",
                                "proofValue": "0x1a4e1c250eb0654b1d2dbd5a6b65ffd1483d37fa9c0ef2ef5bf5b9f52d129ccf0ce43beaad86b0d4ade03f33c8b1825a38ba6417576b79f50485380d1dfdad661b",
                                "verificationMethod": "did:pkh:eip155:59141:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
                                "created": "2024-10-14T12:22:31.970Z",
                                "eip712": {
                                    "types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
                                    "primaryType": "Iden3PaymentRailsRequestV1",
                                    "domain": {
                                        "name": "MCPayment",
                                        "version": "1.0.0",
                                        "chainId": "59141",
                                        "verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
                                        "salt": ""
                                    }
                                }
                            }
                        ]
                    }
                ],
                "credentials": [
                    {
                        "type": "AML",
                        "context": "http://test.com"
                    }
                ],
                "description": "Iden3PaymentRailsRequestV1 payment-request integration test"
            }
        ]
    }
}
`

	for _, tc := range []struct {
		desc            string
		payload         []byte
		expectedPayload []byte
	}{
		{
			desc:            "PaymentRequestMessage of type PaymentRequestCryptoV1",
			payload:         []byte(paymentRequestTypeIden3PaymentRequestCryptoV1),
			expectedPayload: []byte(paymentRequestTypeIden3PaymentRequestCryptoV1),
		},
		{
			desc:            "PaymentRequestMessage of type Iden3PaymentRailsRequestV1",
			payload:         []byte(paymentRequestTypeIden3PaymentRailsRequestV1),
			expectedPayload: []byte(paymentRequestTypeIden3PaymentRailsRequestV1),
		},
	} {

		t.Run(tc.desc, func(t *testing.T) {
			var msg PaymentRequestMessage
			err := json.Unmarshal(tc.payload, &msg)
			require.NoError(t, err)
			payload, err := json.Marshal(msg)
			require.NoError(t, err)
			assert.JSONEq(t, string(tc.expectedPayload), string(payload))

		})
	}
}

func TestEthereumEip712Signature2021Col(t *testing.T) {
	const eip712Signature2021InList = `
				[
					{
						"type": "EthereumEip712Signature2021",
						"proofPurpose": "assertionMethod",
						"proofValue": "0x1a4e1c250eb0654b1d2dbd5a6b65ffd1483d37fa9c0ef2ef5bf5b9f52d129ccf0ce43beaad86b0d4ade03f33c8b1825a38ba6417576b79f50485380d1dfdad661b",
						"verificationMethod": "did:pkh:eip155:59141:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
						"created": "2024-10-14T12:22:31.970Z",
						"eip712": {
							"types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
							"primaryType": "Iden3PaymentRailsRequestV1",
							"domain": {
								"name": "MCPayment",
								"version": "1.0.0",
								"chainId": "59141",
								"verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
								"salt": ""
							}
						}
					}
				]
`

	const eip712Signature2021Single = `
				{
					"type": "EthereumEip712Signature2021",
					"proofPurpose": "assertionMethod",
					"proofValue": "0x1a4e1c250eb0654b1d2dbd5a6b65ffd1483d37fa9c0ef2ef5bf5b9f52d129ccf0ce43beaad86b0d4ade03f33c8b1825a38ba6417576b79f50485380d1dfdad661b",
					"verificationMethod": "did:pkh:eip155:59141:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
					"created": "2024-10-14T12:22:31.970Z",
					"eip712": {
						"types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
						"primaryType": "Iden3PaymentRailsRequestV1",
						"domain": {
							"name": "MCPayment",
							"version": "1.0.0",
							"chainId": "59141",
							"verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
							"salt": ""
						}
					}
				}
`
	for _, tc := range []struct {
		desc            string
		payload         []byte
		expectedPayload []byte
	}{
		{
			desc:            "eip712Signature2021 unmarshalling from a list but marshaling to a list",
			payload:         []byte(eip712Signature2021InList),
			expectedPayload: []byte(eip712Signature2021InList),
		},
		{
			desc:            "eip712Signature2021 unmarshalling from an element & marshaling to a list",
			payload:         []byte(eip712Signature2021Single),
			expectedPayload: []byte(eip712Signature2021InList),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var msg EthereumEip712Signature2021Col
			require.NoError(t, json.Unmarshal(tc.payload, &msg))
			payload, err := json.Marshal(msg)
			require.NoError(t, err)
			assert.JSONEq(t, string(tc.expectedPayload), string(payload))
		})
	}

}

func TestPaymentRequestInfoDataUnmarshalMarshall(t *testing.T) {
	const paymentRequestCryptoV1InList = `
				[
					{
						"type":"Iden3PaymentRequestCryptoV1",
						"amount":"10",
						"id": "ox",
						"chainId": "80002",
						"address": "0xpay1",
						"currency": "ETH",
						"expiration": "<timestamp>"
					}
				]
`
	const paymentRequestCryptoV1Single = `
				{
					"type":"Iden3PaymentRequestCryptoV1",
					"amount":"10",
					"id": "ox",
					"chainId": "80002",
					"address": "0xpay1",
					"currency": "ETH",
					"expiration": "<timestamp>"
				}

`

	const paymentRequestRailsV1InList = `
				[
                    {
                        "type": "Iden3PaymentRailsRequestV1",
                        "@context": [
                            "https://schema.iden3.io/core/jsonld/payment.jsonld#Iden3PaymentRailsRequestV1",
                            "https://w3id.org/security/suites/eip712sig-2021/v1"
                        ],
                        "recipient": "0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a",
                        "amount": "30001",
                        "currency": "ETHWEI",
                        "expirationDate": "2024-10-14T13:22:31.956Z",
                        "nonce": "18",
                        "metadata": "0x",
                        "proof": [
                            {
                                "type": "EthereumEip712Signature2021",
                                "proofPurpose": "assertionMethod",
                                "proofValue": "0xd881e175b548b940406e8ed97e0fe58134ac93e381cb53c35f940040b1d890540cc9f4c0f3bf42b35d3dc72d29b203af5cbae968fafc1342332f63c3581a8e691b",
                                "verificationMethod": "did:pkh:eip155:80002:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
                                "created": "2024-10-14T12:22:31.964Z",
                                "eip712": {
                                    "types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
                                    "primaryType": "Iden3PaymentRailsRequestV1",
                                    "domain": {
                                        "name": "MCPayment",
                                        "version": "1.0.0",
                                        "chainId": "80002",
                                        "verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
                                        "salt": ""
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "type": "Iden3PaymentRailsRequestV1",
                        "@context": [
                            "https://schema.iden3.io/core/jsonld/payment.jsonld#Iden3PaymentRailsRequestV1",
                            "https://w3id.org/security/suites/eip712sig-2021/v1"
                        ],
                        "recipient": "0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a",
                        "amount": "60002",
                        "currency": "ETHWEI",
                        "expirationDate": "2024-10-14T13:22:31.956Z",
                        "nonce": "18",
                        "metadata": "0x",
                        "proof": [
                            {
                                "type": "EthereumEip712Signature2021",
                                "proofPurpose": "assertionMethod",
                                "proofValue": "0xd3606f34447c437ef7c13a1e407ad75597ee0229590de286e5775d1f1335ff93601d7a6398d69a4a3e2ddb4da5e30e61ef388d2ad6e0b50041731eaf3afe41ad1b",
                                "verificationMethod": "did:pkh:eip155:1101:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
                                "created": "2024-10-14T12:22:31.967Z",
                                "eip712": {
                                    "types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
                                    "primaryType": "Iden3PaymentRailsRequestV1",
                                    "domain": {
                                        "name": "MCPayment",
                                        "version": "1.0.0",
                                        "chainId": "1101",
                                        "verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
                                        "salt": ""
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "type": "Iden3PaymentRailsRequestV1",
                        "@context": [
                            "https://schema.iden3.io/core/jsonld/payment.jsonld#Iden3PaymentRailsRequestV1",
                            "https://w3id.org/security/suites/eip712sig-2021/v1"
                        ],
                        "recipient": "0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a",
                        "amount": "90003",
                        "currency": "ETHWEI",
                        "expirationDate": "2024-10-14T13:22:31.956Z",
                        "nonce": "18",
                        "metadata": "0x",
                        "proof": [
                            {
                                "type": "EthereumEip712Signature2021",
                                "proofPurpose": "assertionMethod",
                                "proofValue": "0x1a4e1c250eb0654b1d2dbd5a6b65ffd1483d37fa9c0ef2ef5bf5b9f52d129ccf0ce43beaad86b0d4ade03f33c8b1825a38ba6417576b79f50485380d1dfdad661b",
                                "verificationMethod": "did:pkh:eip155:59141:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a#blockchainAccountId",
                                "created": "2024-10-14T12:22:31.970Z",
                                "eip712": {
                                    "types": "https://schema.iden3.io/core/json/Iden3PaymentRailsRequestV1.json",
                                    "primaryType": "Iden3PaymentRailsRequestV1",
                                    "domain": {
                                        "name": "MCPayment",
                                        "version": "1.0.0",
                                        "chainId": "59141",
                                        "verifyingContract": "0x74Ac6aa5dDC433A654d84aFCE5D95c32df16cC0A",
                                        "salt": ""
                                    }
                                }
                            }
                        ]
                    }
                ]
			`
	for _, tc := range []struct {
		desc            string
		payload         []byte
		expectedPayload []byte
	}{
		{
			desc:            "PaymentRequestCryptoV1 unmarshalling from an element & marshaling to a single element",
			payload:         []byte(paymentRequestCryptoV1InList),
			expectedPayload: []byte(paymentRequestCryptoV1Single),
		},
		{
			desc:            "PaymentRequestCryptoV1 unmarshalling from a list but marshaling to a single element",
			payload:         []byte(paymentRequestCryptoV1InList),
			expectedPayload: []byte(paymentRequestCryptoV1Single),
		},
		{
			desc:            "Iden3PaymentRailsRequestV1 multiple elements inside a list",
			payload:         []byte(paymentRequestRailsV1InList),
			expectedPayload: []byte(paymentRequestRailsV1InList),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var msg PaymentRequestInfoData
			require.NoError(t, json.Unmarshal(tc.payload, &msg))
			payload, err := json.Marshal(msg)
			require.NoError(t, err)
			assert.JSONEq(t, string(tc.expectedPayload), string(payload))
		})
	}
}

func TestPaymentContext(t *testing.T) {
	for _, tc := range []struct {
		desc            string
		payload         []byte
		expectedPayload []byte
	}{
		{
			desc:            "A string",
			payload:         []byte(`"context"`),
			expectedPayload: []byte(`"context"`),
		},
		{
			desc:            "A string in a list",
			payload:         []byte(`["context"]`),
			expectedPayload: []byte(`["context"]`),
		},
		{
			desc:            "A list of strings",
			payload:         []byte(`["context1", "context2"]`),
			expectedPayload: []byte(`["context1", "context2"]`),
		},
		{
			desc:            "A list of heterogeneous objects",
			payload:         []byte(`[{"field":"context1"}, "context in a string"]`),
			expectedPayload: []byte(`[{"field":"context1"}, "context in a string"]`),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var msg PaymentContext
			require.NoError(t, json.Unmarshal(tc.payload, &msg))
			payload, err := json.Marshal(msg)
			require.NoError(t, err)
			assert.JSONEq(t, string(tc.expectedPayload), string(payload))
		})
	}
}