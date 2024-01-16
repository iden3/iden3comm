package resolvers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gofrs/uuid/v5"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/pkg/errors"
)

// AgentResolverConfig options for credential status verification
type AgentResolverConfig struct {
	PackageManager *iden3comm.PackageManager
	UserDID        *w3c.DID
	IssuerDID      *w3c.DID
}

// AgentResolverOpts returns configuration options for AgentResolverOpts
type AgentResolverOpts func(opts *AgentResolverConfig)

// WithPackageManager return new options
func WithPackageManager(pm *iden3comm.PackageManager) AgentResolverOpts {
	return func(opts *AgentResolverConfig) {
		opts.PackageManager = pm
	}
}

// WithUserDID return new options
func WithUserDID(userDID *w3c.DID) AgentResolverOpts {
	return func(opts *AgentResolverConfig) {
		opts.UserDID = userDID
	}
}

// WithIssuerDID return new options
func WithIssuerDID(issuerDID *w3c.DID) AgentResolverOpts {
	return func(opts *AgentResolverConfig) {
		opts.IssuerDID = issuerDID
	}
}

// AgentResolver is a struct that allows to interact with the issuer's agent to get revocation status.
type AgentResolver struct {
	config AgentResolverConfig
}

// Resolve is a method to resolve a credential status from an agent.
func (r AgentResolver) Resolve(_ context.Context, status verifiable.CredentialStatus) (out verifiable.RevocationStatus, err error) {
	revocationBody := protocol.RevocationStatusRequestMessageBody{
		RevocationNonce: status.RevocationNonce,
	}
	rawBody, err := json.Marshal(revocationBody)
	if err != nil {
		return out, errors.WithStack(err)
	}

	idUUID, err := uuid.NewV4()
	if err != nil {
		return out, err
	}
	threadUUID, err := uuid.NewV4()
	if err != nil {
		return out, err
	}
	msg := iden3comm.BasicMessage{
		ID:       idUUID.String(),
		ThreadID: threadUUID.String(),
		From:     r.config.UserDID.String(),
		To:       r.config.IssuerDID.String(),
		Type:     protocol.RevocationStatusRequestMessageType,
		Body:     rawBody,
	}
	bytesMsg, err := json.Marshal(msg)
	if err != nil {
		return out, errors.WithStack(err)
	}

	iden3commMsg, err := r.config.PackageManager.Pack(packers.MediaTypePlainMessage, bytesMsg, nil)
	if err != nil {
		return out, errors.WithStack(err)
	}

	resp, err := http.DefaultClient.Post(status.ID, "application/json", bytes.NewBuffer(iden3commMsg))
	if err != nil {
		return out, errors.WithStack(err)
	}
	defer func() {
		err2 := resp.Body.Close()
		if err != nil {
			err = errors.WithStack(err2)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return out, errors.Errorf("bad status code: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, errors.WithStack(err)
	}

	basicMessage, _, err := r.config.PackageManager.Unpack(b)
	if err != nil {
		return out, errors.WithStack(err)
	}

	if basicMessage.Type != protocol.RevocationStatusResponseMessageType {
		return out, errors.Errorf("unexpected message type: %s", basicMessage.Type)
	}

	var revocationStatus protocol.RevocationStatusResponseMessageBody
	if err := json.Unmarshal(basicMessage.Body, &revocationStatus); err != nil {
		return out, errors.WithStack(err)
	}

	return revocationStatus.RevocationStatus, nil
}
