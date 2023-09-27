package compute

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/google/compute"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableShieldedVMIntegrityMonitoring(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance shielded VM integrity monitoring disabled",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:                   defsecTypes.NewTestMetadata(),
							IntegrityMonitoringEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance shielded VM integrity monitoring enabled",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:                   defsecTypes.NewTestMetadata(),
							IntegrityMonitoringEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			results := CheckEnableShieldedVMIntegrityMonitoring.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableShieldedVMIntegrityMonitoring.Rule().LongID() {
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
