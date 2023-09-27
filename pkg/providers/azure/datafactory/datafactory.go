package datafactory

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	Metadata            defsecTypes.Metadata
	EnablePublicNetwork defsecTypes.BoolValue
}
