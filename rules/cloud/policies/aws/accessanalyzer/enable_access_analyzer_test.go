package accessanalyzer

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/providers/aws/accessanalyzer"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckNoSecretsInUserData(t *testing.T) {
	tests := []struct {
		name     string
		input    accessanalyzer.AccessAnalyzer
		expected bool
	}{
		{
			name:     "No analyzers enabled",
			input:    accessanalyzer.AccessAnalyzer{},
			expected: true,
		},
		{
			name: "Analyzer disabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						ARN:      defsecTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", defsecTypes.NewTestMetadata()),
						Name:     defsecTypes.String("test", defsecTypes.NewTestMetadata()),
						Active:   defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Analyzer enabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						ARN:      defsecTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", defsecTypes.NewTestMetadata()),
						Name:     defsecTypes.String("test", defsecTypes.NewTestMetadata()),
						Active:   defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.AccessAnalyzer = test.input
			results := CheckEnableAccessAnalyzer.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAccessAnalyzer.Rule().LongID() {
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
