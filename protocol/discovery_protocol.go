package protocol

import "github.com/iden3/iden3comm/v2"

// DiscoveryProtocolFeatureType is type for query feature-type.
type DiscoveryProtocolFeatureType string

const (
	// DiscoveryProtocolFeatureTypeAccept is "accept" type for query feature-type.
	DiscoveryProtocolFeatureTypeAccept DiscoveryProtocolFeatureType = "accept"

	// DiscoveryProtocolFeatureTypeProtocol is "protocol" type for query feature-type.
	DiscoveryProtocolFeatureTypeProtocol DiscoveryProtocolFeatureType = "protocol"

	// DiscoveryProtocolFeatureTypeGoalCode is "goal-code" type for query feature-type.
	DiscoveryProtocolFeatureTypeGoalCode DiscoveryProtocolFeatureType = "goal-code"

	// DiscoveryProtocolFeatureTypeHeader is "header" type for query feature-type.
	DiscoveryProtocolFeatureTypeHeader DiscoveryProtocolFeatureType = "header"
)

// DiscoverFeatureQueriesMessage represents discover feature queries message.
type DiscoverFeatureQueriesMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body DiscoverFeatureQueriesMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`
}

// DiscoverFeatureQueriesMessageBody represents the body of the DiscoverFeatureQueriesMessage.
type DiscoverFeatureQueriesMessageBody struct {
	Queries []DiscoverFeatureQuery `json:"queries"`
}

// DiscoverFeatureQuery represents discover feature query.
type DiscoverFeatureQuery struct {
	FeatureType DiscoveryProtocolFeatureType `json:"feature-type"`
	Match       string                       `json:"match,omitempty"`
}

// DiscoverFeatureDiscloseMessage represents discover feature disclose message.
type DiscoverFeatureDiscloseMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body DiscoverFeatureDiscloseMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	CreatedTime *int64 `json:"created_time,omitempty"`
	ExpiresTime *int64 `json:"expires_time,omitempty"`
}

// DiscoverFeatureDiscloseMessageBody represents the body of the DiscoverFeatureDiscloseMessage.
type DiscoverFeatureDiscloseMessageBody struct {
	Disclosures []DiscoverFeatureDisclosure `json:"disclosures"`
}

// DiscoverFeatureDisclosure represents discover feature disclosure.
type DiscoverFeatureDisclosure struct {
	FeatureType DiscoveryProtocolFeatureType `json:"feature-type"`
	ID          string                       `json:"id"`
}
