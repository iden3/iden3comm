package utils

import (
	"errors"
	"testing"

	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
)

func TestAcceptProfileParser(t *testing.T) {
	type expected struct {
		profile protocol.AcceptProfile
		err     error
	}
	for _, tc := range []struct {
		desc     string
		accept   string
		expected expected
	}{
		{
			desc:   "Valid plain text accept profile",
			accept: "iden3comm/v1;env=application/iden3comm-plain-json",
			expected: expected{
				profile: protocol.AcceptProfile{
					ProtocolVersion: protocol.ProtocolVersionV1,
					Env:             packers.MediaTypePlainMessage,
				},
			},
		},
		{
			desc:   "Valid anoncrypt accept profile",
			accept: "iden3comm/v1;env=application/iden3comm-encrypted-json;alg=ECDH-ES+A256KW",
			expected: expected{
				profile: protocol.AcceptProfile{
					ProtocolVersion:           protocol.ProtocolVersionV1,
					Env:                       packers.MediaTypeEncryptedMessage,
					AcceptAnoncryptAlgorithms: []protocol.AcceptAnoncryptAlgorithms{protocol.AcceptAnoncryptECDHESA256KW},
				},
			},
		},
		{
			desc:   "Valid JWS accept profile",
			accept: "iden3comm/v1;env=application/iden3comm-signed-json;alg=ES256K-R",
			expected: expected{
				profile: protocol.AcceptProfile{
					ProtocolVersion:     protocol.ProtocolVersionV1,
					Env:                 packers.MediaTypeSignedMessage,
					AcceptJwsAlgorithms: []protocol.AcceptJwsAlgorithms{protocol.AcceptJwsAlgorithmsES256KR},
				},
			},
		},
		{
			desc:   "Valid JWZ accept profile",
			accept: "iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV2,authV3;alg=groth16",
			expected: expected{
				profile: protocol.AcceptProfile{
					ProtocolVersion:     protocol.ProtocolVersionV1,
					Env:                 packers.MediaTypeZKPMessage,
					AcceptJwzAlgorithms: []protocol.AcceptJwzAlgorithms{protocol.AcceptJwzAlgorithmsGroth16},
					Circuits:            []protocol.AcceptAuthCircuits{protocol.AcceptAuthCircuitsAuthV2, protocol.AcceptAuthCircuitsAuthV3},
				},
			},
		},
		{
			desc:   "Invalid accept profile",
			accept: "iden3comm/v1",
			expected: expected{
				err: errors.New("invalid accept profile value"),
			},
		},
		{
			desc:   "Invalid protocol version profile",
			accept: "iden3comm/v1000_000;env=application/iden3comm-plain-json",
			expected: expected{
				err: errors.New("protocol version 'iden3comm/v1000_000' not supported"),
			},
		},
		{
			desc:   "Invalid envelop param",
			accept: "iden3comm/v1;application/iden3comm-plain-json",
			expected: expected{
				err: errors.New("invalid accept profile 'env' parameter"),
			},
		},
		{
			desc:   "Invalid envelop",
			accept: "iden3comm/v1;env=application/iden3comm-rich-text",
			expected: expected{
				err: errors.New("envelop 'application/iden3comm-rich-text' not supported"),
			},
		},
		{
			desc:   "Invalid circuit ID",
			accept: "iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV2.5;alg=groth16",
			expected: expected{
				err: errors.New("circuit 'authV2.5' not supported"),
			},
		},
		{
			desc:   "Invalid alg",
			accept: "iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV2;alg=groth1",
			expected: expected{
				err: errors.New("algorithm 'groth1' not supported for 'application/iden3-zkp-json'"),
			},
		},
		{
			desc:   "Alg for plain message",
			accept: "iden3comm/v1;env=application/iden3comm-plain-json;alg=someAlg",
			expected: expected{
				err: errors.New("algorithm not supported for 'application/iden3comm-plain-json'"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			profile, err := ParseAcceptProfile(tc.accept)
			if tc.expected.err != nil {
				assert.Equal(t, err.Error(), tc.expected.err.Error())
			}
			assert.Equal(t, profile, tc.expected.profile)
		})
	}
}
