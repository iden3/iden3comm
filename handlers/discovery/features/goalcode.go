package features

import (
	"context"

	"github.com/iden3/iden3comm/v2/protocol"
)

// GoalCodeFeaturer implementation
// # Experimental
type GoalCodeFeaturer struct {
	goalCodes []string
}

// GoalCodeOption configures a GoalCodeFeaturer
// # Experimental
type GoalCodeOption func(*GoalCodeFeaturer)

// WithGoalCodes sets custom goal codes for GoalCodeFeaturer
// # Experimental
func WithGoalCodes(goalCodes ...string) GoalCodeOption {
	return func(g *GoalCodeFeaturer) {
		g.goalCodes = goalCodes
	}
}

// NewGoalCodeFeaturer constructor
// # Experimental
func NewGoalCodeFeaturer(opts ...GoalCodeOption) *GoalCodeFeaturer {
	g := &GoalCodeFeaturer{}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Handle implementation for GoalCodeFeaturer
// # Experimental
func (g *GoalCodeFeaturer) Handle(ctx context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := make([]protocol.DiscoverFeatureDisclosure, 0, len(g.goalCodes))

	for _, goalCode := range g.goalCodes {
		disclosures = append(disclosures, protocol.DiscoverFeatureDisclosure{
			FeatureType: protocol.DiscoveryProtocolFeatureTypeGoalCode,
			ID:          goalCode,
		})
	}

	return disclosures
}
