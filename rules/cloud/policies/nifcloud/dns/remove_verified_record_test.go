package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/dns"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/state"
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

func TestCheckRemoveVerifiedRecord(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name:     "No records",
			input:    dns.DNS{},
			expected: false,
		},
		{
			name: "Some record",
			input: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String("A", defsecTypes.NewTestMetadata()),
						Record:   defsecTypes.String("some", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Some TXT record",
			input: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String("TXT", defsecTypes.NewTestMetadata()),
						Record:   defsecTypes.String("some", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},

		{
			name: "Verify TXT record",
			input: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String("TXT", defsecTypes.NewTestMetadata()),
						Record:   defsecTypes.String(dns.ZoneRegistrationAuthTxt, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.DNS = test.input
			results := CheckRemoveVerifiedRecord.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRemoveVerifiedRecord.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
