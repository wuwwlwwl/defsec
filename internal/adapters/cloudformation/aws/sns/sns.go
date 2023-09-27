package sns

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/sns"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) sns.SNS {
	return sns.SNS{
		Topics: getTopics(cfFile),
	}
}
