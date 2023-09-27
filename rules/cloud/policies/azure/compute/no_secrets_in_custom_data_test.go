package compute

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/compute"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoSecretsInCustomData(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Secrets in custom data",
			input: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   defsecTypes.NewTestMetadata(),
							CustomData: defsecTypes.String(`export DATABASE_PASSWORD=\"SomeSortOfPassword\"`, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "No secrets in custom data",
			input: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   defsecTypes.NewTestMetadata(),
							CustomData: defsecTypes.String(`export GREETING="Hello there"`, defsecTypes.NewTestMetadata()),
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
			results := CheckNoSecretsInCustomData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoSecretsInCustomData.Rule().LongID() {
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
