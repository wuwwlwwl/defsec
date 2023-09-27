package compute

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type ProjectMetadata struct {
	Metadata      defsecTypes.Metadata
	EnableOSLogin defsecTypes.BoolValue
}
