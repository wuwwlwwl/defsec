package iam

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/providers/google/iam"

	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/tftestutil"
	"github.com/wuwwlwwl/defsec/test/testutil"
)

func Test_AdaptBinding(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.Binding
	}{
		{
			name: "defined",
			terraform: `
		resource "google_organization_iam_binding" "binding" {
			org_id = data.google_organization.org.id
			role    = "roles/browser"
			
			members = [
				"user:alice@gmail.com",
			]
		}`,
			expected: iam.Binding{
				Metadata: defsecTypes.NewTestMetadata(),
				Members: []defsecTypes.StringValue{
					defsecTypes.String("user:alice@gmail.com", defsecTypes.NewTestMetadata())},
				Role:                          defsecTypes.String("roles/browser", defsecTypes.NewTestMetadata()),
				IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
		resource "google_organization_iam_binding" "binding" {
		}`,
			expected: iam.Binding{
				Metadata:                      defsecTypes.NewTestMetadata(),
				Role:                          defsecTypes.String("", defsecTypes.NewTestMetadata()),
				IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := AdaptBinding(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
