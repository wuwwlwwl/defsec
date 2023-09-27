package storage

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/storage"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDefaultActionDeny(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage network rule allows access by default",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								AllowByDefault: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage network rule denies access by default",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								AllowByDefault: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
			testState.Azure.Storage = test.input
			results := CheckDefaultActionDeny.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDefaultActionDeny.Rule().LongID() {
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
