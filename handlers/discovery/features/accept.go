package features

import (
	"context"

	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"
)

// AcceptFeaturer implementation
type AcceptFeaturer struct {
	packageManager *iden3comm.PackageManager
}

// NewAcceptFeaturer constructor
func NewAcceptFeaturer(packageManager *iden3comm.PackageManager) *AcceptFeaturer {
	return &AcceptFeaturer{
		packageManager: packageManager,
	}
}

// Handle implementation for AcceptFeaturer
func (a *AcceptFeaturer) Handle(ctx context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := []protocol.DiscoverFeatureDisclosure{}

	profiles := a.packageManager.GetSupportedProfiles()
	for _, profile := range profiles {
		disclosures = append(disclosures, protocol.DiscoverFeatureDisclosure{
			FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
			ID:          profile,
		})
	}
	return disclosures
}
