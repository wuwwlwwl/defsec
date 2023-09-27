package network

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/network"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) network.Network {

	return network.Network{
		ElasticLoadBalancers: adaptElasticLoadBalancers(modules),
		LoadBalancers:        adaptLoadBalancers(modules),
		Routers:              adaptRouters(modules),
		VpnGateways:          adaptVpnGateways(modules),
	}
}
