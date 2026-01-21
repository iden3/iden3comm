package features

import (
	"context"

	"github.com/iden3/iden3comm/v2/protocol"
)

// HeaderFeaturer implementation
// # Experimental
type HeaderFeaturer struct {
	headers []string
}

// HeaderOption configures a HeaderFeaturer
// # Experimental
type HeaderOption func(*HeaderFeaturer)

// WithHeaders sets custom headers for HeaderFeaturer
// # Experimental
func WithHeaders(headers ...string) HeaderOption {
	return func(h *HeaderFeaturer) {
		h.headers = headers
	}
}

// NewHeaderFeaturer constructor accepts functional options.
// If no headers option is provided, it falls back to the defaultHeaders.
// # Experimental
func NewHeaderFeaturer(opts ...HeaderOption) *HeaderFeaturer {
	h := &HeaderFeaturer{
		headers: []string{
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
		},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Handle implementation for HeaderFeaturer
// # Experimental
func (h *HeaderFeaturer) Handle(ctx context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := make([]protocol.DiscoverFeatureDisclosure, 0, len(h.headers))

	for _, header := range h.headers {
		disclosures = append(disclosures, protocol.DiscoverFeatureDisclosure{
			FeatureType: protocol.DiscoveryProtocolFeatureTypeHeader,
			ID:          header,
		})
	}

	return disclosures
}
