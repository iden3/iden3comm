package discovery

import (
	"context"

	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"
)

// Featurer interface for feature handlers
type Featurer interface {
	Handle(ctx context.Context) []protocol.DiscoverFeatureDisclosure
}

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

// ProtocolFeaturer implementation
type ProtocolFeaturer struct {
	supportedProtocols []iden3comm.ProtocolMessage
}

// NewProtocolFeaturer constructor
func NewProtocolFeaturer(supportedProtocols []iden3comm.ProtocolMessage) *ProtocolFeaturer {
	return &ProtocolFeaturer{
		supportedProtocols: supportedProtocols,
	}
}

// Handle implementation for ProtocolFeaturer
func (p *ProtocolFeaturer) Handle(ctx context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := []protocol.DiscoverFeatureDisclosure{}
	for _, protocolMessage := range p.supportedProtocols {
		disclosures = append(disclosures, protocol.DiscoverFeatureDisclosure{
			FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
			ID:          string(protocolMessage),
		})
	}
	return disclosures
}

// GoalCodeFeaturer implementation
type GoalCodeFeaturer struct{}

// NewGoalCodeFeaturer constructor
func NewGoalCodeFeaturer() *GoalCodeFeaturer {
	return &GoalCodeFeaturer{}
}

// Handle implementation for GoalCodeFeaturer
func (g *GoalCodeFeaturer) Handle(ctx context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := []protocol.DiscoverFeatureDisclosure{}
	return disclosures
}

// HeaderFeaturer implementation
type HeaderFeaturer struct{}

// NewHeaderFeaturer constructor
func NewHeaderFeaturer() *HeaderFeaturer {
	return &HeaderFeaturer{}
}

// Handle implementation for HeaderFeaturer
func (h *HeaderFeaturer) Handle(ctx context.Context) []protocol.DiscoverFeatureDisclosure {
	headers := []string{
		"id",
		"typ",
		"type",
		"thid",
		"body",
		"from",
		"to",
		"created_time",
		"expires_time",
		"attachments",
	}

	disclosures := []protocol.DiscoverFeatureDisclosure{}

	for _, header := range headers {
		disclosures = append(disclosures, protocol.DiscoverFeatureDisclosure{
			FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
			ID:          header,
		})
	}

	return disclosures
}
