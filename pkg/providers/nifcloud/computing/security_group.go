package computing

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type SecurityGroup struct {
	Metadata     defsecTypes.Metadata
	Description  defsecTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
	CIDR        defsecTypes.StringValue
}
