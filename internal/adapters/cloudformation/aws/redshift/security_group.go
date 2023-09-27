package redshift

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/redshift"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
)

func getSecurityGroups(ctx parser.FileContext) (groups []redshift.SecurityGroup) {
	for _, groupResource := range ctx.GetResourcesByType("AWS::Redshift::ClusterSecurityGroup") {
		group := redshift.SecurityGroup{
			Metadata:    groupResource.Metadata(),
			Description: groupResource.GetProperty("Description").AsStringValue(),
		}
		groups = append(groups, group)
	}
	return groups
}
