package nas

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/nas"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) nas.NAS {
	return nas.NAS{
		NASSecurityGroups: adaptNASSecurityGroups(modules),
		NASInstances:      adaptNASInstances(modules),
	}
}
