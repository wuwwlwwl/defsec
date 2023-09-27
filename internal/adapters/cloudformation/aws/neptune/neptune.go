package neptune

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/neptune"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) neptune.Neptune {
	return neptune.Neptune{
		Clusters: getClusters(cfFile),
	}
}
