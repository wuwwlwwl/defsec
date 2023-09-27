package sam

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/aws/sam"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableApiAccessLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "API logging not configured",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              defsecTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API logging configured",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              defsecTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: defsecTypes.String("log-group-arn", defsecTypes.NewTestMetadata()),
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
			results := CheckEnableApiAccessLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableApiAccessLogging.Rule().LongID() {
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
