package ec2

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type Volume struct {
	Metadata   defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}
