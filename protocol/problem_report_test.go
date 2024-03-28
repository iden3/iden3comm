package protocol

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewProblemReportErrorCode(t *testing.T) {
	type expected struct {
		code ProblemErrorCode
		err  error
	}
	for _, tc := range []struct {
		desc        string
		sorter      string
		scope       string
		descriptors []string
		expected    expected
	}{
		{
			desc:   "Sorter should be e or w",
			sorter: "x",
			scope:  "scope",
			expected: expected{
				err: errors.New("invalid sorter. allowed values [e:error, w:warning]"),
			},
		},
		{
			desc:   "At lease one descriptor is required",
			sorter: ProblemReportTypeError,
			scope:  "scope",
			expected: expected{
				err: errors.New("at least one descriptor is required"),
			},
		},
		{
			desc:   "Scope must be kebab-case 1",
			sorter: ProblemReportTypeError,
			scope:  "scope-",
			expected: expected{
				err: errors.New("invalid scope. must be kebab-case"),
			},
		},
		{
			desc:   "Scope must be kebab-case 2",
			sorter: ProblemReportTypeWarning,
			scope:  "-scope",
			expected: expected{
				err: errors.New("invalid scope. must be kebab-case"),
			},
		},
		{
			desc:   "Scope must be kebab-case 3",
			sorter: ProblemReportTypeError,
			scope:  "a---scope",
			expected: expected{
				err: errors.New("invalid scope. must be kebab-case"),
			},
		},
		{
			desc:        "Happy path, one descriptor",
			sorter:      ProblemReportTypeWarning,
			scope:       ReportDescriptorTransport,
			descriptors: []string{"remote-server-down"},
			expected: expected{
				code: "w.xfer.remote-server-down",
			},
		},
		{
			desc:        "Happy path, multiple descriptors",
			sorter:      ProblemReportTypeError,
			scope:       ReportDescriptorTransport,
			descriptors: []string{"cant-use-endpoint", "dns-failed"},
			expected: expected{
				code: "e.xfer.cant-use-endpoint.dns-failed",
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := NewProblemReportErrorCode(tc.sorter, tc.scope, tc.descriptors)
			if tc.expected.err != nil {
				assert.Equal(t, err.Error(), tc.expected.err.Error())
			}
			assert.Equal(t, c, tc.expected.code)
		})
	}
}

func TestParseProblemErrorCode(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		code        string
		descriptors []string
		err         error
	}{
		{
			desc: "Empty code",
			code: "",
			err:  errors.New("invalid error code. format sorter.scope.descriptors"),
		},
		{
			desc: "One field",
			code: ProblemReportTypeWarning,
			err:  errors.New("invalid error code. format sorter.scope.descriptors"),
		},
		{
			desc: "No descriptor",
			code: ProblemReportTypeWarning + ReportDescriptorTransport,
			err:  errors.New("invalid error code. format sorter.scope.descriptors"),
		},
		{
			desc: "Happy Path, one descriptor",
			code: "w.xfer.remote-server-down",
			err:  nil,
		},
		{
			desc: "Happy Path, multiple descriptors",
			code: "w.xfer.remote-server-down.desc2.desc3.descN",
			err:  nil,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := ParseProblemErrorCode(tc.code)
			if tc.err != nil {
				assert.Equal(t, err.Error(), tc.err.Error())
				assert.Empty(t, c)

			} else {
				assert.NoError(t, err)
				assert.Equal(t, ProblemErrorCode(tc.code), c)
			}

		})
	}
}
