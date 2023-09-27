package cloudformation

import (
	"github.com/wuwwlwwl/defsec/internal/adapters/cloudformation/aws"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
