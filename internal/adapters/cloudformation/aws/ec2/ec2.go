package ec2

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/ec2"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ec2.EC2 {
	return ec2.EC2{
		LaunchConfigurations: getLaunchConfigurations(cfFile),
		LaunchTemplates:      getLaunchTemplates(cfFile),
		Instances:            getInstances(cfFile),
		VPCs:                 nil,
		NetworkACLs:          getNetworkACLs(cfFile),
		SecurityGroups:       getSecurityGroups(cfFile),
		Subnets:              getSubnets(cfFile),
		Volumes:              getVolumes(cfFile),
	}
}
