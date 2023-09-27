package ecr

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/ecr"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ecr.ECR {
	return ecr.ECR{
		Repositories: getRepositories(cfFile),
	}
}
