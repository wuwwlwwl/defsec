package nas

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type NASInstance struct {
	Metadata  defsecTypes.Metadata
	NetworkID defsecTypes.StringValue
}
