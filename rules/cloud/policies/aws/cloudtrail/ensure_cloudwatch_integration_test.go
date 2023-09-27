package cloudtrail

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/stretchr/testify/assert"
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/cloudtrail"
)

func TestCheckEnsureCloudwatchIntegration(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudtrail.CloudTrail
		expected bool
	}{
		{
			name: "Trail has cloudwatch configured",
			input: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  defsecTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: defsecTypes.String("arn:aws:logs:us-east-1:123456789012:log-group:my-log-group", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Trail does not have cloudwatch configured",
			input: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  defsecTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudTrail = test.input
			results := checkEnsureCloudwatchIntegration.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkEnsureCloudwatchIntegration.Rule().LongID() {
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
