package compute

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/compute"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDisablePasswordAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Linux VM password authentication enabled",
			input: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      defsecTypes.NewTestMetadata(),
							DisablePasswordAuthentication: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Linux VM password authentication disabled",
			input: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      defsecTypes.NewTestMetadata(),
							DisablePasswordAuthentication: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.Azure.Compute = test.input
			results := CheckDisablePasswordAuthentication.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDisablePasswordAuthentication.Rule().LongID() {
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
