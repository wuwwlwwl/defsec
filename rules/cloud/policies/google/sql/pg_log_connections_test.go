package sql

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/google/sql"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPgLogConnections(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance connections logging disabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        defsecTypes.NewTestMetadata(),
						DatabaseVersion: defsecTypes.String("POSTGRES_12", defsecTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       defsecTypes.NewTestMetadata(),
								LogConnections: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance connections logging enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        defsecTypes.NewTestMetadata(),
						DatabaseVersion: defsecTypes.String("POSTGRES_12", defsecTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       defsecTypes.NewTestMetadata(),
								LogConnections: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.Google.SQL = test.input
			results := CheckPgLogConnections.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPgLogConnections.Rule().LongID() {
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
