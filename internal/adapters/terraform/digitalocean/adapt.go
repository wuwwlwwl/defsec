package digitalocean

import (
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/digitalocean/compute"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/digitalocean/spaces"
	"github.com/wuwwlwwl/defsec/pkg/providers/digitalocean"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}
