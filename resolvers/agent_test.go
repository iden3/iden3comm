package resolvers

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"net/http"
	"net/http/httptest"

	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentResolver(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"body":{"issuer":{"claimsTreeRoot":"d9597e2fef206c9821f2425e513a68c8c793bc93c9216fb883fedaaf72abf51c","revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000","rootOfRoots":"eaa48e4a7d3fe2fabbd939c7df1048c3f647a9a7c9dfadaae836ec78ba673229","state":"96161f3fbbdd68c72bc430dae474e27b157586b33b9fbf4a3f07d75ce275570f"},"mtp":{"existence":false,"siblings":[]}},"from":"did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ","id":"9ece0dad-9267-4a52-b611-f0615b0143fb","thid":"8bdc87dc-1755-41d5-b483-26562836068e","to":"did:polygonid:polygon:mumbai:2qFDziX3k3h7To2jDJbQiXFtcozbgSNNvQpb6TgtPE","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/revocation/1.0/status"}`))
	}))
	defer mockServer.Close()

	credStatusJSON := fmt.Sprintf(`{
		"id": "%s",
		"revocationNonce": 3262660310,
		"type": "Iden3commRevocationStatusV1.0"
	}`, mockServer.URL)

	var credStatus verifiable.CredentialStatus
	err := json.Unmarshal([]byte(credStatusJSON), &credStatus)
	require.NoError(t, err)

	pm := iden3comm.NewPackageManager()
	err = pm.RegisterPackers(&packers.PlainMessagePacker{})
	require.NoError(t, err)

	issuerDID, err := w3c.ParseDID("did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ")
	require.NoError(t, err)
	senderDID, err := w3c.ParseDID("did:polygonid:polygon:mumbai:2qFDziX3k3h7To2jDJbQiXFtcozbgSNNvQpb6TgtPE")
	require.NoError(t, err)

	agentConfig := AgentResolverConfig{
		PackageManager: pm,
	}

	agentResolver := NewAgentResolver(agentConfig)

	ctx := context.Background()
	ctx = verifiable.WithIssuerDID(ctx, issuerDID)
	ctx = WithSenderDID(ctx, senderDID)
	revocationStatus, err := agentResolver.Resolve(ctx, credStatus)
	require.NoError(t, err)

	expectedRevocationStatusJSON := `{"issuer":{"state":"96161f3fbbdd68c72bc430dae474e27b157586b33b9fbf4a3f07d75ce275570f","rootOfRoots":"eaa48e4a7d3fe2fabbd939c7df1048c3f647a9a7c9dfadaae836ec78ba673229","claimsTreeRoot":"d9597e2fef206c9821f2425e513a68c8c793bc93c9216fb883fedaaf72abf51c","revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000"},"mtp":{"existence":false,"siblings":[]}}`
	var expectedRevocationStatus verifiable.RevocationStatus
	err = json.Unmarshal([]byte(expectedRevocationStatusJSON), &expectedRevocationStatus)
	require.NoError(t, err)

	assert.Equal(t, revocationStatus, expectedRevocationStatus)

}
