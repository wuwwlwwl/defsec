package network

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/network"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
	"github.com/wuwwlwwl/defsec/pkg/types"
)

func adaptRouters(modules terraform.Modules) []network.Router {
	var routers []network.Router

	for _, resource := range modules.GetResourcesByType("nifcloud_router") {
		routers = append(routers, adaptRouter(resource))
	}
	return routers
}

func adaptRouter(resource *terraform.Block) network.Router {
	var networkInterfaces []network.NetworkInterface
	networkInterfaceBlocks := resource.GetBlocks("network_interface")
	for _, networkInterfaceBlock := range networkInterfaceBlocks {
		networkInterfaces = append(
			networkInterfaces,
			network.NetworkInterface{
				Metadata:     networkInterfaceBlock.GetMetadata(),
				NetworkID:    networkInterfaceBlock.GetAttribute("network_id").AsStringValueOrDefault("", resource),
				IsVipNetwork: types.Bool(false, networkInterfaceBlock.GetMetadata()),
			},
		)
	}

	return network.Router{
		Metadata:          resource.GetMetadata(),
		SecurityGroup:     resource.GetAttribute("security_group").AsStringValueOrDefault("", resource),
		NetworkInterfaces: networkInterfaces,
	}
}
