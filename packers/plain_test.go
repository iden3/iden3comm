package packers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlainSupportedProfiles(t *testing.T) {
	p := PlainMessagePacker{}
	acceptProfiles := p.GetSupportedProfiles()
	require.Equal(t, []string{"iden3comm/v1;env=application/iden3comm-plain-json"}, acceptProfiles)
}
