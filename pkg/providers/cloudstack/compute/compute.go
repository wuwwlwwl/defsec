package compute

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	Metadata defsecTypes.Metadata
	UserData defsecTypes.StringValue // not b64 encoded pls
}
