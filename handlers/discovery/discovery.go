package discovery

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
)

// Discovery handler
type Discovery struct {
	features map[protocol.DiscoveryProtocolFeatureType]Featurer
}

// New creates a new Discovery handler
func New(features map[protocol.DiscoveryProtocolFeatureType]Featurer) *Discovery {
	return &Discovery{
		features: features,
	}
}

// Handle processes a DiscoverFeatureQueriesMessage and returns a DiscoverFeatureDiscloseMessage
func (d *Discovery) Handle(ctx context.Context,
	discoverInputMessage protocol.DiscoverFeatureQueriesMessage) (protocol.DiscoverFeatureDiscloseMessage, error) {
	queries := discoverInputMessage.Body.Queries

	var (
		disclosures []protocol.DiscoverFeatureDisclosure
		err         error
	)

	for _, query := range queries {
		var disclosuresToAppend []protocol.DiscoverFeatureDisclosure
		if featurer, ok := d.features[query.FeatureType]; ok {
			disclosuresToAppend = featurer.Handle(ctx)
		}

		disclosuresToAppend, err = d.handleMatch(disclosuresToAppend, query.Match)
		if err != nil {
			return protocol.DiscoverFeatureDiscloseMessage{}, err
		}
		disclosures = append(disclosures, disclosuresToAppend...)
	}

	return protocol.DiscoverFeatureDiscloseMessage{
		ID:       uuid.NewString(),
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.DiscoverFeatureDiscloseMessageType,
		ThreadID: discoverInputMessage.ThreadID,
		Body: protocol.DiscoverFeatureDiscloseMessageBody{
			Disclosures: disclosures,
		},
		From: discoverInputMessage.To,
		To:   discoverInputMessage.From,
	}, nil
}

func (d *Discovery) handleMatch(disclosures []protocol.DiscoverFeatureDisclosure, match string) ([]protocol.DiscoverFeatureDisclosure, error) {
	if match == "" || match == "*" {
		return disclosures, nil
	}

	regExp, err := wildcardToRegExp(match)
	if err != nil {
		return nil, err
	}
	var filtered []protocol.DiscoverFeatureDisclosure
	for _, disclosure := range disclosures {
		if regExp.MatchString(disclosure.ID) {
			filtered = append(filtered, disclosure)
		}
	}
	return filtered, nil
}

func wildcardToRegExp(match string) (*regexp.Regexp, error) {
	// Escape special regex characters and replace `*` with `.*`
	regexPattern := regexp.QuoteMeta(match)
	regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")
	return regexp.Compile("^" + regexPattern + "$")
}
