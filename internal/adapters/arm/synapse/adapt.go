package synapse

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/synapse"
	"github.com/wuwwlwwl/defsec/pkg/scanners/azure"
	"github.com/wuwwlwwl/defsec/pkg/types"
)

func Adapt(deployment azure.Deployment) synapse.Synapse {
	return synapse.Synapse{
		Workspaces: adaptWorkspaces(deployment),
	}
}

func adaptWorkspaces(deployment azure.Deployment) (workspaces []synapse.Workspace) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Synapse/workspaces") {
		workspaces = append(workspaces, adaptWorkspace(resource))
	}
	return workspaces
}

func adaptWorkspace(resource azure.Resource) synapse.Workspace {

	managedVirtualNetwork := resource.Properties.GetMapValue("managedVirtualNetwork").AsString()
	enableManagedVirtualNetwork := types.BoolDefault(false, resource.Metadata)
	if managedVirtualNetwork == "default" {
		enableManagedVirtualNetwork = types.Bool(true, resource.Metadata)
	}

	return synapse.Workspace{
		Metadata:                    resource.Metadata,
		EnableManagedVirtualNetwork: enableManagedVirtualNetwork,
	}
}
