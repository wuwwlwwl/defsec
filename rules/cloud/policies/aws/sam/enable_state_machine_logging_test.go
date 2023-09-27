package sam

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/aws/sam"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStateMachineLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "State machine logging disabled",
			input: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       defsecTypes.NewTestMetadata(),
							LoggingEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "State machine logging enabled",
			input: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       defsecTypes.NewTestMetadata(),
							LoggingEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckEnableStateMachineLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStateMachineLogging.Rule().LongID() {
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
