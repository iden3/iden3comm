package protocol_test

import (
	"encoding/json"
	"testing"

	uuid "github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)

func TestDiscoverFeatureQueriesMessageCreation(t *testing.T) {

	var err error
	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	queryMessage := protocol.DiscoverFeatureQueriesMessage{
		ID:       id.String(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.DiscoverFeatureQueriesMessageType,
		ThreadID: thID.String(),
		Body: protocol.DiscoverFeatureQueriesMessageBody{
			Queries: []protocol.DiscoverFeatureQuery{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
					Match:       "https://iden3-communication.io/authorization/1.*",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
				},
			},
		},
		From: "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE",
	}

	marshalledReq, err := json.Marshal(queryMessage)
	require.NoError(t, err)

	require.JSONEq(t, `{
		"id": "f0885dd0-e60e-11ee-b3e8-de17148ce1ce",
		"typ": "application/iden3comm-plain-json",
		"type": "https://didcomm.org/discover-features/2.0/queries",
		"thid": "f08860d2-e60e-11ee-b3e8-de17148ce1ce",
		"body": {
		  "queries": [
			{
			  "feature-type": "accept"
			},
			{
			  "feature-type": "protocol",
			  "match": "https://iden3-communication.io/authorization/1.*"
			},
			{
			  "feature-type": "header"
			}
		  ]
		},
		"from": "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	  }`, string(marshalledReq))
}

func TestDiscoverFeatureDisclosuresMessageCreation(t *testing.T) {

	var err error
	id, err := uuid.Parse("f0885dd0-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	thID, err := uuid.Parse("f08860d2-e60e-11ee-b3e8-de17148ce1ce")
	require.NoError(t, err)

	queryMessage := protocol.DiscoverFeatureDiscloseMessage{
		ID:       id.String(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.DiscoverFeatureDiscloseMessageType,
		ThreadID: thID.String(),
		Body: protocol.DiscoverFeatureDiscloseMessageBody{
			Disclosures: []protocol.DiscoverFeatureDisclosure{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					Id:          "iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV2,authV3;alg=groth16",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					Id:          "iden3comm/v1;env=application/iden3comm-signed-json;alg=ES256K-R",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
					Id:          "https://iden3-communication.io/authorization/1.0",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
					Id:          "id",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
					Id:          "type",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
					Id:          "body",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
					Id:          "created_time",
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
					Id:          "expires_time",
				},
			},
		},
		To: "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE",
	}

	marshalledReq, err := json.Marshal(queryMessage)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"id": "f0885dd0-e60e-11ee-b3e8-de17148ce1ce",
		"typ": "application/iden3comm-plain-json",
		"type": "https://didcomm.org/discover-features/2.0/disclose",
		"thid": "f08860d2-e60e-11ee-b3e8-de17148ce1ce",
		"body": {
		  "disclosures": [
			{
			  "feature-type": "accept",
			  "id": "iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV2,authV3;alg=groth16"
			},
			{
			  "feature-type": "accept",
			  "id": "iden3comm/v1;env=application/iden3comm-signed-json;alg=ES256K-R"
			},
			{
			  "feature-type": "protocol",
			  "id": "https://iden3-communication.io/authorization/1.0"
			},
			{
			  "feature-type": "header",
			  "id": "id"
			},
			{
			  "feature-type": "header",
			  "id": "type"
			},
			{
			  "feature-type": "header",
			  "id": "body"
			},
			{
			  "feature-type": "header",
			  "id": "created_time"
			},
			{
			  "feature-type": "header",
			  "id": "expires_time"
			}
		  ]
		},
		"to": "did:polygonid:polygon:mumbai:2qK2Rwf2zqzzhqVLqTWXetGUbs1Sc79woomP5cDLBE"
	  }`, string(marshalledReq))
}
