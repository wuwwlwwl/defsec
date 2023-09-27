package network

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type LoadBalancer struct {
	Metadata  defsecTypes.Metadata
	Listeners []LoadBalancerListener
}

type LoadBalancerListener struct {
	Metadata  defsecTypes.Metadata
	Protocol  defsecTypes.StringValue
	TLSPolicy defsecTypes.StringValue
}
