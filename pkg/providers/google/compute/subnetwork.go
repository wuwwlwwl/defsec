package compute

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type SubNetwork struct {
	Metadata       defsecTypes.Metadata
	Name           defsecTypes.StringValue
	EnableFlowLogs defsecTypes.BoolValue
}
