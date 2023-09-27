package nas

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/nas"

	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/tftestutil"

	"github.com/wuwwlwwl/defsec/test/testutil"
)

func Test_adaptNASInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []nas.NASInstance
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_nas_instance" "example" {
				network_id = "example-network"
			}
`,
			expected: []nas.NASInstance{{
				Metadata:  defsecTypes.NewTestMetadata(),
				NetworkID: defsecTypes.String("example-network", defsecTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_nas_instance" "example" {
			}
`,

			expected: []nas.NASInstance{{
				Metadata:  defsecTypes.NewTestMetadata(),
				NetworkID: defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNASInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
