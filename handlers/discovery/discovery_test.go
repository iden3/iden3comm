package discovery_test

import (
	"context"
	"testing"

	"github.com/iden3/go-jwz/v2"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/handlers/discovery"
	"github.com/iden3/iden3comm/v2/handlers/discovery/features"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type want struct {
	FeatureType    protocol.DiscoveryProtocolFeatureType
	ParsedFeatures discovery.Feature
	ID             string
}

func TestDiscovery_Handle(t *testing.T) {
	tests := []struct {
		name                 string
		discoveryFactory     func(t *testing.T) *discovery.Discovery
		discoverInputMessage protocol.DiscoverFeatureQueriesMessage
		want                 []want
	}{
		{
			name: "Support only zkp packer with authV3 groth16 and authV3-8-32 groth16",
			discoveryFactory: func(t *testing.T) *discovery.Discovery {
				zkpPacker := packers.NewZKPPacker(
					map[jwz.ProvingMethodAlg]packers.ProvingParams{},
					map[jwz.ProvingMethodAlg]packers.VerificationParams{
						jwz.AuthV3Groth16Alg:      {},
						jwz.AuthV3_8_32Groth16Alg: {},
					},
				)

				pm := iden3comm.NewPackageManager()
				err := pm.RegisterPackers(zkpPacker)
				require.NoError(t, err)

				return discovery.New(map[protocol.DiscoveryProtocolFeatureType]discovery.Featurer{
					protocol.DiscoveryProtocolFeatureTypeAccept:   features.NewAcceptFeaturer(pm),
					protocol.DiscoveryProtocolFeatureTypeProtocol: features.NewProtocolFeaturer([]iden3comm.ProtocolMessage{}),
					protocol.DiscoveryProtocolFeatureTypeGoalCode: features.NewGoalCodeFeaturer(),
					protocol.DiscoveryProtocolFeatureTypeHeader:   features.NewHeaderFeaturer(),
				})
			},
			discoverInputMessage: newDiscoverFeatureQueriesMessage([]protocol.DiscoverFeatureQuery{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
				},
			}),
			want: []want{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					ParsedFeatures: discovery.Feature{
						Version: "iden3comm/v1",
						Env:     "application/iden3-zkp-json",
						Algs:    []string{"groth16"},
						CircuitIds: []string{
							"authV3",
							"authV3-8-32",
						},
					},
				},
			},
		},
		{
			name: "Support zkp, plain text packers with authV3 groth16 and authV3-8-32 groth16",
			discoveryFactory: func(t *testing.T) *discovery.Discovery {
				zkpPacker := packers.NewZKPPacker(
					map[jwz.ProvingMethodAlg]packers.ProvingParams{},
					map[jwz.ProvingMethodAlg]packers.VerificationParams{
						jwz.AuthV3Groth16Alg:      {},
						jwz.AuthV3_8_32Groth16Alg: {},
					},
				)

				pm := iden3comm.NewPackageManager()
				err := pm.RegisterPackers(zkpPacker, &packers.PlainMessagePacker{})
				require.NoError(t, err)

				return discovery.New(map[protocol.DiscoveryProtocolFeatureType]discovery.Featurer{
					protocol.DiscoveryProtocolFeatureTypeAccept:   features.NewAcceptFeaturer(pm),
					protocol.DiscoveryProtocolFeatureTypeProtocol: features.NewProtocolFeaturer([]iden3comm.ProtocolMessage{}),
					protocol.DiscoveryProtocolFeatureTypeGoalCode: features.NewGoalCodeFeaturer(),
					protocol.DiscoveryProtocolFeatureTypeHeader:   features.NewHeaderFeaturer(),
				})
			},
			discoverInputMessage: newDiscoverFeatureQueriesMessage([]protocol.DiscoverFeatureQuery{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
				},
			}),
			want: []want{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					ParsedFeatures: discovery.Feature{
						Version: "iden3comm/v1",
						Env:     "application/iden3-zkp-json",
						Algs:    []string{"groth16"},
						CircuitIds: []string{
							"authV3",
							"authV3-8-32",
						},
					},
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					ParsedFeatures: discovery.Feature{
						Version: "iden3comm/v1",
						Env:     "application/iden3comm-plain-json",
					},
				},
			},
		},
		{
			name: "Support message type: credential proposal request, credential fetch",
			discoveryFactory: func(t *testing.T) *discovery.Discovery {
				pm := iden3comm.NewPackageManager()
				err := pm.RegisterPackers(&packers.PlainMessagePacker{})
				require.NoError(t, err)

				return discovery.New(map[protocol.DiscoveryProtocolFeatureType]discovery.Featurer{
					protocol.DiscoveryProtocolFeatureTypeAccept: features.NewAcceptFeaturer(pm),
					protocol.DiscoveryProtocolFeatureTypeProtocol: features.NewProtocolFeaturer([]iden3comm.ProtocolMessage{
						protocol.CredentialProposalRequestMessageType,
						protocol.CredentialFetchRequestMessageType,
					}),
					protocol.DiscoveryProtocolFeatureTypeGoalCode: features.NewGoalCodeFeaturer(),
					protocol.DiscoveryProtocolFeatureTypeHeader:   features.NewHeaderFeaturer(),
				})
			},
			discoverInputMessage: newDiscoverFeatureQueriesMessage([]protocol.DiscoverFeatureQuery{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
				},
			}),
			want: []want{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
					ID:          string(protocol.CredentialProposalRequestMessageType),
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
					ID:          string(protocol.CredentialFetchRequestMessageType),
				},
			},
		},
		{
			name: "Support feature and protocol requests",
			discoveryFactory: func(t *testing.T) *discovery.Discovery {
				pm := iden3comm.NewPackageManager()
				err := pm.RegisterPackers(&packers.PlainMessagePacker{})
				require.NoError(t, err)

				return discovery.New(map[protocol.DiscoveryProtocolFeatureType]discovery.Featurer{
					protocol.DiscoveryProtocolFeatureTypeAccept: features.NewAcceptFeaturer(pm),
					protocol.DiscoveryProtocolFeatureTypeProtocol: features.NewProtocolFeaturer([]iden3comm.ProtocolMessage{
						protocol.CredentialProposalRequestMessageType,
						protocol.CredentialFetchRequestMessageType,
					}),
					protocol.DiscoveryProtocolFeatureTypeGoalCode: features.NewGoalCodeFeaturer(),
					protocol.DiscoveryProtocolFeatureTypeHeader:   features.NewHeaderFeaturer(),
				})
			},
			discoverInputMessage: newDiscoverFeatureQueriesMessage([]protocol.DiscoverFeatureQuery{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
				},
			}),
			want: []want{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
					ID:          string(protocol.CredentialProposalRequestMessageType),
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
					ID:          string(protocol.CredentialFetchRequestMessageType),
				},
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					ParsedFeatures: discovery.Feature{
						Version: "iden3comm/v1",
						Env:     "application/iden3comm-plain-json",
					},
				},
			},
		},
		{
			name: "With match wildcard. Filter only application/iden3comm-plain-json packers",
			discoveryFactory: func(t *testing.T) *discovery.Discovery {
				zkpPacker := packers.NewZKPPacker(
					map[jwz.ProvingMethodAlg]packers.ProvingParams{},
					map[jwz.ProvingMethodAlg]packers.VerificationParams{
						jwz.AuthV3Groth16Alg:      {},
						jwz.AuthV3_8_32Groth16Alg: {},
					},
				)

				pm := iden3comm.NewPackageManager()
				err := pm.RegisterPackers(zkpPacker, &packers.PlainMessagePacker{})
				require.NoError(t, err)

				return discovery.New(map[protocol.DiscoveryProtocolFeatureType]discovery.Featurer{
					protocol.DiscoveryProtocolFeatureTypeAccept:   features.NewAcceptFeaturer(pm),
					protocol.DiscoveryProtocolFeatureTypeProtocol: features.NewProtocolFeaturer([]iden3comm.ProtocolMessage{}),
					protocol.DiscoveryProtocolFeatureTypeGoalCode: features.NewGoalCodeFeaturer(),
					protocol.DiscoveryProtocolFeatureTypeHeader:   features.NewHeaderFeaturer(),
				})
			},
			discoverInputMessage: newDiscoverFeatureQueriesMessage([]protocol.DiscoverFeatureQuery{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					Match:       "*iden3comm-plain-json",
				},
			}),
			want: []want{
				{
					FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
					ParsedFeatures: discovery.Feature{
						Version: "iden3comm/v1",
						Env:     "application/iden3comm-plain-json",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.discoveryFactory(t)
			actual, err := d.Handle(
				context.Background(),
				tt.discoverInputMessage,
			)
			testActualID(t, actual.Body.Disclosures, tt.want)
			require.NoError(t, err)

		})
	}
}

func testActualID(t *testing.T, actual []protocol.DiscoverFeatureDisclosure, want []want) {
	require.Equal(t, len(actual), len(want))
	// try to find actual in want
	for _, a := range actual {
		found := false
		for i, w := range want {
			if a.FeatureType != w.FeatureType {
				continue
			}

			if a.FeatureType == protocol.DiscoveryProtocolFeatureTypeAccept {
				isEqual := isEqualAcceptFeature(a, w.ParsedFeatures)
				if isEqual {
					// nullify to avoid duplicate matching
					want = nullify(want, i)
					found = true
					break
				}
			}
			// for another types, just match by FeatureType and ID
			if a.ID == w.ID {
				// nullify to avoid duplicate matching
				want = nullify(want, i)
				found = true
				break
			}
		}
		require.True(t, found, "actual ID not found in want: %v", a)
	}
}

type mockT struct{}

func (m *mockT) Errorf(format string, args ...interface{}) {}

func isEqualAcceptFeature(actual protocol.DiscoverFeatureDisclosure, want discovery.Feature) bool {
	parsed := discovery.ParseFeature(actual.ID)

	if want.Version != parsed.Version {
		return false
	}
	if want.Env != parsed.Env {
		return false
	}

	t := &mockT{}
	return assert.ElementsMatch(t, want.Algs, parsed.Algs) &&
		assert.ElementsMatch(t, want.CircuitIds, parsed.CircuitIds)
}

func nullify(w []want, index int) []want {
	w[index] = want{}
	return w
}

func newDiscoverFeatureQueriesMessage(queries []protocol.DiscoverFeatureQuery) protocol.DiscoverFeatureQueriesMessage {
	return protocol.DiscoverFeatureQueriesMessage{
		ID:       "c0fc0f29-4f34-4bea-851b-58b7639fe29c",
		ThreadID: "becfc675-b15d-4817-98a5-7fce0240a48a",
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.DiscoverFeatureQueriesMessageType,
		Body: protocol.DiscoverFeatureQueriesMessageBody{
			Queries: queries,
		},
	}
}
