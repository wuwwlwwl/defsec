package synapse

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/synapse"

	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/tftestutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wuwwlwwl/defsec/test/testutil"
)

func Test_adaptWorkspace(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  synapse.Workspace
	}{
		{
			name: "enabled",
			terraform: `
			resource "azurerm_synapse_workspace" "example" {
				managed_virtual_network_enabled	   = true
			}
`,
			expected: synapse.Workspace{
				Metadata:                    defsecTypes.NewTestMetadata(),
				EnableManagedVirtualNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "disabled",
			terraform: `
			resource "azurerm_synapse_workspace" "example" {
				managed_virtual_network_enabled	   = false
			}
`,
			expected: synapse.Workspace{
				Metadata:                    defsecTypes.NewTestMetadata(),
				EnableManagedVirtualNetwork: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "default",
			terraform: `
			resource "azurerm_synapse_workspace" "example" {
			}
`,
			expected: synapse.Workspace{
				Metadata:                    defsecTypes.NewTestMetadata(),
				EnableManagedVirtualNetwork: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWorkspace(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_synapse_workspace" "example" {
		managed_virtual_network_enabled	   = true
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Workspaces, 1)
	workspace := adapted.Workspaces[0]

	assert.Equal(t, 3, workspace.EnableManagedVirtualNetwork.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, workspace.EnableManagedVirtualNetwork.GetMetadata().Range().GetEndLine())
}
