package terraform

import (
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/aws"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/azure"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/cloudstack"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/digitalocean"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/github"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/kubernetes"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/nifcloud"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/openstack"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/oracle"
	"github.com/wuwwlwwl/defsec/pkg/state"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) *state.State {
	return &state.State{
		AWS:          aws.Adapt(modules),
		Azure:        azure.Adapt(modules),
		CloudStack:   cloudstack.Adapt(modules),
		DigitalOcean: digitalocean.Adapt(modules),
		GitHub:       github.Adapt(modules),
		Google:       google.Adapt(modules),
		Kubernetes:   kubernetes.Adapt(modules),
		Nifcloud:     nifcloud.Adapt(modules),
		OpenStack:    openstack.Adapt(modules),
		Oracle:       oracle.Adapt(modules),
	}
}
