package compute

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type SSLPolicy struct {
	Metadata          defsecTypes.Metadata
	Name              defsecTypes.StringValue
	Profile           defsecTypes.StringValue
	MinimumTLSVersion defsecTypes.StringValue
}
