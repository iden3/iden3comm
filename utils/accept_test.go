package utils

import (
	"errors"
	"testing"

	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
)

func TestBuildAcceptProfile(t *testing.T) {
	type expected struct {
		accept []string
		err    error
	}
	for _, tc := range []struct {
		desc     string
		profile  []protocol.AcceptProfile
		expected expected
	}{
		{
			desc: "Valid plain text accept profile",
			profile: []protocol.AcceptProfile{{
				AcceptedVersion: protocol.Iden3CommVersion1,
				Env:             mediaTypePlainMessage,
			}},
			expected: expected{
				accept: []string{"iden3comm/v1;env=application/iden3comm-plain-json"},
			},
		},
		{
			desc: "Valid anoncrypt accept profile",
			profile: []protocol.AcceptProfile{{
				AcceptedVersion:           protocol.Iden3CommVersion1,
				Env:                       mediaTypeEncryptedMessage,
				AcceptAnoncryptAlgorithms: []protocol.AnoncryptAlgorithms{protocol.AnoncryptECDHESA256KW},
			}},
			expected: expected{
				accept: []string{"iden3comm/v1;env=application/iden3comm-encrypted-json;alg=ECDH-ES+A256KW"},
			},
		},
		{
			desc: "Valid JWS accept profile",
			profile: []protocol.AcceptProfile{{
				AcceptedVersion:     protocol.Iden3CommVersion1,
				Env:                 mediaTypeJWSMessage,
				AcceptJwsAlgorithms: []protocol.JwsAlgorithms{protocol.JwsAlgorithmsES256KR},
			}},
			expected: expected{
				accept: []string{"iden3comm/v1;env=application/iden3comm-signed-json;alg=ES256K-R"},
			},
		},
		{
			desc: "Valid JWZ accept profile",
			profile: []protocol.AcceptProfile{{
				AcceptedVersion:     protocol.Iden3CommVersion1,
				Env:                 mediaTypeZKPMessage,
				AcceptJwzAlgorithms: []protocol.JwzAlgorithms{protocol.JwzAlgorithmsGroth16},
				AcceptCircuits:      []protocol.AuthCircuits{protocol.AuthCircuitsAuthV2, protocol.AuthCircuitsAuthV3},
			}},
			expected: expected{
				accept: []string{"iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV2,authV3;alg=groth16"},
			},
		},
		{
			desc: "Circuit ID for JWS",
			profile: []protocol.AcceptProfile{{
				AcceptedVersion:     protocol.Iden3CommVersion1,
				Env:                 mediaTypeJWSMessage,
				AcceptJwsAlgorithms: []protocol.JwsAlgorithms{protocol.JwsAlgorithmsES256K},
				AcceptCircuits:      []protocol.AuthCircuits{protocol.AuthCircuitsAuthV2, protocol.AuthCircuitsAuthV3},
			}},
			expected: expected{
				err: errors.New("circuits not supported for env 'application/iden3comm-signed-json'"),
			},
		},
		{
			desc: "Wrong alg fro media type",
			profile: []protocol.AcceptProfile{{
				AcceptedVersion:           protocol.Iden3CommVersion1,
				Env:                       mediaTypeJWSMessage,
				AcceptAnoncryptAlgorithms: []protocol.AnoncryptAlgorithms{protocol.AnoncryptECDHESA256KW},
			}},
			expected: expected{
				err: errors.New("anoncrypt algorithms not supported for env 'application/iden3comm-signed-json'"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			profile, err := BuildAcceptProfile(tc.profile)
			if tc.expected.err != nil {
				assert.Equal(t, err.Error(), tc.expected.err.Error())
			}
			assert.Equal(t, profile, tc.expected.accept)
		})
	}
}

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
					AcceptedVersion: protocol.Iden3CommVersion1,
					Env:             mediaTypePlainMessage,
				},
			},
		},
		{
			desc:   "Valid anoncrypt accept profile",
			accept: "iden3comm/v1;env=application/iden3comm-encrypted-json;alg=ECDH-ES+A256KW",
			expected: expected{
				profile: protocol.AcceptProfile{
					AcceptedVersion:           protocol.Iden3CommVersion1,
					Env:                       mediaTypeEncryptedMessage,
					AcceptAnoncryptAlgorithms: []protocol.AnoncryptAlgorithms{protocol.AnoncryptECDHESA256KW},
				},
			},
		},
		{
			desc:   "Valid JWS accept profile",
			accept: "iden3comm/v1;env=application/iden3comm-signed-json;alg=ES256K-R",
			expected: expected{
				profile: protocol.AcceptProfile{
					AcceptedVersion:     protocol.Iden3CommVersion1,
					Env:                 mediaTypeJWSMessage,
					AcceptJwsAlgorithms: []protocol.JwsAlgorithms{protocol.JwsAlgorithmsES256KR},
				},
			},
		},
		{
			desc:   "Valid JWZ accept profile",
			accept: "iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV2,authV3;alg=groth16",
			expected: expected{
				profile: protocol.AcceptProfile{
					AcceptedVersion:     protocol.Iden3CommVersion1,
					Env:                 mediaTypeZKPMessage,
					AcceptJwzAlgorithms: []protocol.JwzAlgorithms{protocol.JwzAlgorithmsGroth16},
					AcceptCircuits:      []protocol.AuthCircuits{protocol.AuthCircuitsAuthV2, protocol.AuthCircuitsAuthV3},
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
