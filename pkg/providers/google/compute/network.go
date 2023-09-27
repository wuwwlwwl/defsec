package compute

import (
	"github.com/wuwwlwwl/defsec/pkg/types"
)

type Network struct {
	Metadata    types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
