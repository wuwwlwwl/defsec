package appservice

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/appservice"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAccountIdentityRegistered(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "App service identity not registered",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Identity: struct{ Type defsecTypes.StringValue }{
							Type: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "App service identity registered",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Identity: struct{ Type defsecTypes.StringValue }{
							Type: defsecTypes.String("UserAssigned", defsecTypes.NewTestMetadata()),
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
			results := CheckAccountIdentityRegistered.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAccountIdentityRegistered.Rule().LongID() {
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
