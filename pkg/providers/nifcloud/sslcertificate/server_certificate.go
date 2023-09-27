package sslcertificate

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type ServerCertificate struct {
	Metadata   defsecTypes.Metadata
	Expiration defsecTypes.TimeValue
}
