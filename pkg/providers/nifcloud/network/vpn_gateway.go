package network

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type VpnGateway struct {
	Metadata      defsecTypes.Metadata
	SecurityGroup defsecTypes.StringValue
}
