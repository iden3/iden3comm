package features_test

import (
	"context"
	"testing"

	"github.com/iden3/iden3comm/v2/handlers/discovery/features"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)

func TestHeaderFeaturer_Handle(t *testing.T) {
	tests := []struct {
		name                string
		supportedHeaders    []string
		expectedDisclosures []protocol.DiscoverFeatureDisclosure
	}{
		{
			name:             "should return default disclosures",
			supportedHeaders: nil,
			expectedDisclosures: []protocol.DiscoverFeatureDisclosure{
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "id"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "typ"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "type"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "thid"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "body"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "from"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "to"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "created_time"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "expires_time"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "attachments"},
			},
		},
		{
			name: "should return id typ only",
			supportedHeaders: []string{
				"id",
				"typ",
			},
			expectedDisclosures: []protocol.DiscoverFeatureDisclosure{
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "id"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader, ID: "typ"},
			},
		},
		{
			name:                "should return empty disclosures",
			supportedHeaders:    []string{},
			expectedDisclosures: []protocol.DiscoverFeatureDisclosure{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var headerFeaturer *features.HeaderFeaturer
			if tc.supportedHeaders == nil {
				headerFeaturer = features.NewHeaderFeaturer()
			} else {
				headerFeaturer = features.NewHeaderFeaturer(features.WithHeaders(tc.supportedHeaders...))
			}

			disclosures := headerFeaturer.Handle(context.Background())
			require.ElementsMatch(t, tc.expectedDisclosures, disclosures)
		})
	}
}
