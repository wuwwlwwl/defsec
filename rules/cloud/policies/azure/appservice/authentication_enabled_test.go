package appservice

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/appservice"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAuthenticationEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "App service authentication disabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Authentication: struct{ Enabled defsecTypes.BoolValue }{
							Enabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "App service authentication enabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Authentication: struct{ Enabled defsecTypes.BoolValue }{
							Enabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.Azure.AppService = test.input
			results := CheckAuthenticationEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAuthenticationEnabled.Rule().LongID() {
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
