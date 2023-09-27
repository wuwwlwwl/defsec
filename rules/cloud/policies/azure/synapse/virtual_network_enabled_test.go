package synapse

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/synapse"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckVirtualNetworkEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    synapse.Synapse
		expected bool
	}{
		{
			name: "Synapse workspace managed VN disabled",
			input: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    defsecTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Synapse workspace managed VN enabled",
			input: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    defsecTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Synapse = test.input
			results := CheckVirtualNetworkEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckVirtualNetworkEnabled.Rule().LongID() {
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
