package efs

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/aws/efs"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    efs.EFS
		expected bool
	}{
		{
			name: "positive result",
			input: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						Encrypted: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					}},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						Encrypted: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					}},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EFS = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.Rule().LongID() {
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
