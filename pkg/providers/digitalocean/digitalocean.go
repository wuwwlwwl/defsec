package digitalocean

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/digitalocean/compute"
	"github.com/wuwwlwwl/defsec/pkg/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}
