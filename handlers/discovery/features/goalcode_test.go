package features_test

import (
	"context"
	"testing"

	"github.com/iden3/iden3comm/v2/handlers/discovery/features"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)

func TestGoalCodeFeaturer_Handle(t *testing.T) {
	tests := []struct {
		name                string
		supportedGoalCodes  []string
		expectedDisclosures []protocol.DiscoverFeatureDisclosure
	}{
		{
			name:                "should return default disclosures",
			supportedGoalCodes:  nil,
			expectedDisclosures: []protocol.DiscoverFeatureDisclosure{},
		},
		{
			name: "should return two goal codes",
			supportedGoalCodes: []string{
				"goal-1",
				"goal-2",
			},
			expectedDisclosures: []protocol.DiscoverFeatureDisclosure{
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeGoalCode, ID: "goal-1"},
				{FeatureType: protocol.DiscoveryProtocolFeatureTypeGoalCode, ID: "goal-2"},
			},
		},
		{
			name:                "should return empty disclosures",
			supportedGoalCodes:  []string{},
			expectedDisclosures: []protocol.DiscoverFeatureDisclosure{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var g *features.GoalCodeFeaturer
			if tc.supportedGoalCodes == nil {
				g = features.NewGoalCodeFeaturer()
			} else {
				g = features.NewGoalCodeFeaturer(features.WithGoalCodes(tc.supportedGoalCodes...))
			}

			disclosures := g.Handle(context.Background())
			require.ElementsMatch(t, tc.expectedDisclosures, disclosures)
		})
	}
}
