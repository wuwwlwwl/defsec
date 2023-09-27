package gke

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/google/gke"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableNetworkPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster network policy disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster network policy enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster autopilot enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						EnableAutpilot: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.GKE = test.input
			results := CheckEnableNetworkPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableNetworkPolicy.Rule().LongID() {
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
