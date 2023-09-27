package dynamodb

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/dynamodb"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{
		DAXClusters: getClusters(cfFile),
	}
}
