package resolvers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gofrs/uuid/v5"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/pkg/errors"
)

// AgentResolverConfig options for credential status verification
type AgentResolverConfig struct {
	PackageManager *iden3comm.PackageManager
}

// AgentResolver is a struct that allows to interact with the issuer's agent to get revocation status.
type AgentResolver struct {
	config AgentResolverConfig
}

// NewAgentResolver returns new agent resolver
func NewAgentResolver(config AgentResolverConfig) *AgentResolver {
	return &AgentResolver{config}
}

// Resolve is a method to resolve a credential status from an agent.
func (r AgentResolver) Resolve(_ context.Context, status verifiable.CredentialStatus, opts *verifiable.CredentialStatusResolveOptions) (out verifiable.RevocationStatus, err error) {
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
		From:     opts.UserDID.String(),
		To:       opts.IssuerDID.String(),
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
