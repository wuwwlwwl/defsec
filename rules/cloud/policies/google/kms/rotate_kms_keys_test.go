package kms

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/google/kms"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRotateKmsKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    kms.KMS
		expected bool
	}{
		{
			name: "KMS key rotation period of 91 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              defsecTypes.NewTestMetadata(),
								RotationPeriodSeconds: defsecTypes.Int(7862400, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "KMS key rotation period of 30 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              defsecTypes.NewTestMetadata(),
								RotationPeriodSeconds: defsecTypes.Int(2592000, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.KMS = test.input
			results := CheckRotateKmsKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRotateKmsKeys.Rule().LongID() {
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
