package iden3comm_test

import (
	"reflect"
	"testing"

	"github.com/iden3/iden3comm/v2"
)

func TestExtractDirectiveFromMessage(t *testing.T) {
	tests := []struct {
		name     string
		message  iden3comm.BasicMessage
		expected []iden3comm.Iden3Directive
	}{
		{
			name: "No directive attachments",
			message: iden3comm.BasicMessage{
				Attachments: iden3comm.Attachments{
					{Type: "otherType"},
				},
			},
			expected: nil,
		},
		{
			name: "With directive attachments",
			message: iden3comm.BasicMessage{
				Attachments: iden3comm.Attachments{
					{
						Type: iden3comm.Iden3DirectiveAttachmentType,
						Data: []iden3comm.Iden3Directive{
							{
								Type: iden3comm.TransparentPaymentDirectiveType,
							},
						},
					},
				},
			},
			expected: []iden3comm.Iden3Directive{
				{
					Type: iden3comm.TransparentPaymentDirectiveType,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.message.Attachments.ExtractDirectives()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestPropagateDirectiveIntoMessage(t *testing.T) {
	tests := []struct {
		name              string
		message           iden3comm.BasicMessage
		incomingDirective []iden3comm.Iden3Directive
		expected          iden3comm.BasicMessage
	}{
		{
			name: "No incoming directives",
			message: iden3comm.BasicMessage{
				ID: "test",
			},
			incomingDirective: []iden3comm.Iden3Directive{},
			expected: iden3comm.BasicMessage{
				ID: "test",
			},
		},
		{
			name: "No existing attachments",
			message: iden3comm.BasicMessage{
				ID: "test",
			},
			incomingDirective: []iden3comm.Iden3Directive{
				{
					Type: iden3comm.TransparentPaymentDirectiveType,
				},
			},
			expected: iden3comm.BasicMessage{
				ID: "test",
				Attachments: iden3comm.Attachments{
					{
						Type: iden3comm.Iden3DirectiveAttachmentType,
						Data: []iden3comm.Iden3Directive{
							{
								Type: iden3comm.TransparentPaymentDirectiveType,
							},
						},
					},
				},
			},
		},
		{
			name: "With existing directive attachments",
			message: iden3comm.BasicMessage{
				ID: "test",
				Attachments: iden3comm.Attachments{
					{
						Type: iden3comm.Iden3DirectiveAttachmentType,
						Data: []iden3comm.Iden3Directive{
							{
								Type: iden3comm.TransparentPaymentDirectiveType,
							},
						},
					},
				},
			},
			incomingDirective: []iden3comm.Iden3Directive{
				{
					Type: iden3comm.TransparentPaymentDirectiveType,
				},
			},
			expected: iden3comm.BasicMessage{
				ID: "test",
				Attachments: iden3comm.Attachments{
					{
						Type: iden3comm.Iden3DirectiveAttachmentType,
						Data: []iden3comm.Iden3Directive{
							{
								Type: iden3comm.TransparentPaymentDirectiveType,
							},
							{
								Type: iden3comm.TransparentPaymentDirectiveType,
							},
						},
					},
				},
			},
		},
		{
			name: "With existing directive attachments and other attachments",
			message: iden3comm.BasicMessage{
				ID: "test",
				Attachments: iden3comm.Attachments{
					{
						Type: "otherType",
					},
				},
			},
			incomingDirective: []iden3comm.Iden3Directive{
				{
					Type: iden3comm.TransparentPaymentDirectiveType,
				},
			},
			expected: iden3comm.BasicMessage{
				ID: "test",
				Attachments: iden3comm.Attachments{
					{
						Type: "otherType",
					},
					{
						Type: iden3comm.Iden3DirectiveAttachmentType,
						Data: []iden3comm.Iden3Directive{
							{
								Type: iden3comm.TransparentPaymentDirectiveType,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.message.Attachments.AddDirectives(tt.incomingDirective)
			if !reflect.DeepEqual(tt.message, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, tt.message)
			}
		})
	}
}
