package ec2

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type Subnet struct {
	Metadata            defsecTypes.Metadata
	MapPublicIpOnLaunch defsecTypes.BoolValue
}
