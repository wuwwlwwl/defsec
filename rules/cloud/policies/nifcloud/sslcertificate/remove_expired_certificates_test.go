package sslcertificate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/sslcertificate"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/state"
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

func TestCheckRemoveExpiredCertificates(t *testing.T) {
	tests := []struct {
		name     string
		input    sslcertificate.SSLCertificate
		expected bool
	}{
		{
			name:     "No certs",
			input:    sslcertificate.SSLCertificate{},
			expected: false,
		},
		{
			name: "Valid cert",
			input: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						Expiration: defsecTypes.Time(time.Now().Add(time.Hour), defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Expired cert",
			input: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						Expiration: defsecTypes.Time(time.Now().Add(-time.Hour), defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.SSLCertificate = test.input
			results := CheckRemoveExpiredCertificates.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRemoveExpiredCertificates.Rule().LongID() {
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
