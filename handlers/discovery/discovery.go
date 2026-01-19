package discovery

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
)

type Discovery struct {
	packerManager      *iden3comm.PackageManager
	supportedProtocols []iden3comm.ProtocolMessage
}

func New(packerManager *iden3comm.PackageManager, supportedProtocols []iden3comm.ProtocolMessage) *Discovery {
	return &Discovery{
		packerManager:      packerManager,
		supportedProtocols: supportedProtocols,
	}
}

func (d *Discovery) Handle(ctx context.Context,
	discoverInputMessage protocol.DiscoverFeatureQueriesMessage) (protocol.DiscoverFeatureDiscloseMessage, error) {
	queries := discoverInputMessage.Body.Queries

	var (
		disclosures []protocol.DiscoverFeatureDisclosure
		err         error
	)

	for _, query := range queries {
		var disclosuresToAppend []protocol.DiscoverFeatureDisclosure
		switch query.FeatureType {
		case protocol.DiscoveryProtocolFeatureTypeAccept:
			disclosuresToAppend = d.handleAccept(ctx)
		case protocol.DiscoveryProtocolFeatureTypeGoalCode:
			disclosuresToAppend = d.handleGoalCode(ctx)
		case protocol.DiscoveryProtocolFeatureTypeProtocol:
			disclosuresToAppend = d.handleProtocol(ctx)
		case protocol.DiscoveryProtocolFeatureTypeHeader:
			disclosuresToAppend = d.handleHeader(ctx)
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

func (d *Discovery) handleAccept(_ context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := []protocol.DiscoverFeatureDisclosure{}

	profiles := d.packerManager.GetSupportedProfiles()
	for _, profile := range profiles {
		disclosures = append(disclosures, protocol.DiscoverFeatureDisclosure{
			FeatureType: protocol.DiscoveryProtocolFeatureTypeAccept,
			ID:          profile,
		})
	}
	return disclosures
}

func (d *Discovery) handleProtocol(_ context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := []protocol.DiscoverFeatureDisclosure{}
	for _, protocolMessage := range d.supportedProtocols {
		disclosures = append(disclosures, protocol.DiscoverFeatureDisclosure{
			FeatureType: protocol.DiscoveryProtocolFeatureTypeProtocol,
			ID:          string(protocolMessage),
		})
	}
	return disclosures
}

func (d *Discovery) handleGoalCode(_ context.Context) []protocol.DiscoverFeatureDisclosure {
	disclosures := []protocol.DiscoverFeatureDisclosure{}
	return disclosures
}

func (d *Discovery) handleHeader(_ context.Context) []protocol.DiscoverFeatureDisclosure {
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
