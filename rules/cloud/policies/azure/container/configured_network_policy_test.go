package container

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/container"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckConfiguredNetworkPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "Cluster missing network policy configuration",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      defsecTypes.NewTestMetadata(),
							NetworkPolicy: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with network policy configured",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      defsecTypes.NewTestMetadata(),
							NetworkPolicy: defsecTypes.String("calico", defsecTypes.NewTestMetadata()),
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
			results := CheckConfiguredNetworkPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckConfiguredNetworkPolicy.Rule().LongID() {
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
