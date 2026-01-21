package features

import (
	"context"

	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"
)

// ProtocolFeaturer implementation
// # Experimental
type ProtocolFeaturer struct {
	supportedProtocols []iden3comm.ProtocolMessage
}

// NewProtocolFeaturer constructor
// # Experimental
func NewProtocolFeaturer(supportedProtocols []iden3comm.ProtocolMessage) *ProtocolFeaturer {
	return &ProtocolFeaturer{
		supportedProtocols: supportedProtocols,
	}
}

// Handle implementation for ProtocolFeaturer
// # Experimental
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
