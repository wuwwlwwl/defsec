package compute

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/google/compute"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDiskEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Disk missing KMS key link",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   defsecTypes.NewTestMetadata(),
							KMSKeyLink: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Disk with KMS key link provided",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   defsecTypes.NewTestMetadata(),
							KMSKeyLink: defsecTypes.String("kms-key-link", defsecTypes.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckDiskEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDiskEncryptionCustomerKey.Rule().LongID() {
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
