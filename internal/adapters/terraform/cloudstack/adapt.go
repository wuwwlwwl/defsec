package cloudstack

import (
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/cloudstack/compute"
	"github.com/wuwwlwwl/defsec/pkg/providers/cloudstack"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
