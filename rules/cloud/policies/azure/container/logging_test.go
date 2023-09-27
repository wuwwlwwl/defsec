package container

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/container"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "Logging via OMS agent disabled",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: defsecTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: defsecTypes.NewTestMetadata(),
								Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Logging via OMS agent enabled",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: defsecTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: defsecTypes.NewTestMetadata(),
								Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.Azure.Container = test.input
			results := CheckLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLogging.Rule().LongID() {
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
