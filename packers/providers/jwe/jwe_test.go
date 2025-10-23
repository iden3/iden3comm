package jwe

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

func TestMergeHeaders(t *testing.T) {
	tests := []struct {
		name            string
		protected       jwe.Headers
		unprotected     jwe.Headers
		perRecipient    jwe.Headers
		expectedHeaders jwe.Headers
	}{
		{
			name:            "all nil headers",
			protected:       nil,
			unprotected:     nil,
			perRecipient:    nil,
			expectedHeaders: jwe.NewHeaders(),
		},
		{
			name: "protected headers only",
			protected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()))
				require.NoError(t, h.Set(jwe.ContentEncryptionKey, jwa.A256GCM()))
				return h
			}(),
			expectedHeaders: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()))
				require.NoError(t, h.Set(jwe.ContentEncryptionKey, jwa.A256GCM()))
				return h
			}(),
		},
		{
			name: "unprotected headers only",
			unprotected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.KeyIDKey, "test-key-id"))
				return h
			}(),
			expectedHeaders: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.KeyIDKey, "test-key-id"))
				return h
			}(),
		},
		{
			name: "per-recipient headers only",
			perRecipient: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.ECDH_ES_A256KW()))
				return h
			}(),
			expectedHeaders: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.ECDH_ES_A256KW()))
				return h
			}(),
		},
		{
			name: "merge all three header types without duplicates",
			protected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.ContentEncryptionKey, jwa.A256GCM()))
				return h
			}(),
			unprotected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.KeyIDKey, "test-key-id"))
				return h
			}(),
			perRecipient: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()))
				return h
			}(),
			expectedHeaders: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.ContentEncryptionKey, jwa.A256GCM()))
				require.NoError(t, h.Set(jwe.KeyIDKey, "test-key-id"))
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()))
				return h
			}(),
		},
		{
			name:            "empty headers objects",
			protected:       jwe.NewHeaders(),
			unprotected:     jwe.NewHeaders(),
			perRecipient:    jwe.NewHeaders(),
			expectedHeaders: jwe.NewHeaders(),
		},
		{
			name: "custom header fields",
			protected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set("custom1", "value1"))
				return h
			}(),
			unprotected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set("custom2", "value2"))
				return h
			}(),
			perRecipient: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set("custom3", "value3"))
				return h
			}(),
			expectedHeaders: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set("custom1", "value1"))
				require.NoError(t, h.Set("custom2", "value2"))
				require.NoError(t, h.Set("custom3", "value3"))
				return h
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := mergeHeaders(tt.protected, tt.unprotected, tt.perRecipient)
			require.NoError(t, err)
			require.Equal(t, tt.expectedHeaders, result)
		})
	}
}

func TestMergeHeaders_Errors(t *testing.T) {
	tests := []struct {
		name         string
		protected    jwe.Headers
		unprotected  jwe.Headers
		perRecipient jwe.Headers
		expectedErr  string
	}{
		{
			name: "duplicate key in protected and unprotected",
			protected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()))
				return h
			}(),
			unprotected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.ECDH_ES_A256KW()))
				return h
			}(),
			expectedErr: "duplicate header key found: alg",
		},
		{
			name: "duplicate key in protected and per-recipient",
			protected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()))
				return h
			}(),
			perRecipient: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.ECDH_ES_A256KW()))
				return h
			}(),
			expectedErr: "duplicate header key found: alg",
		},
		{
			name: "duplicate key in unprotected and per-recipient",
			unprotected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()))
				return h
			}(),
			perRecipient: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.AlgorithmKey, jwa.ECDH_ES_A256KW()))
				return h
			}(),
			expectedErr: "duplicate header key found: alg",
		},
		{
			name: "deuplicate between all three headers",
			protected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.TypeKey, "type-1"))
				return h
			}(),
			unprotected: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.TypeKey, "type-2"))
				return h
			}(),
			perRecipient: func() jwe.Headers {
				h := jwe.NewHeaders()
				require.NoError(t, h.Set(jwe.TypeKey, "type-3"))
				return h
			}(),
			expectedErr: "duplicate header key found: typ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mergeHeaders(tt.protected, tt.unprotected, tt.perRecipient)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}
