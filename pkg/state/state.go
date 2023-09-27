package state

import (
	"reflect"

	"github.com/wuwwlwwl/defsec/pkg/providers/aws"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure"
	"github.com/wuwwlwwl/defsec/pkg/providers/cloudstack"
	"github.com/wuwwlwwl/defsec/pkg/providers/digitalocean"
	"github.com/wuwwlwwl/defsec/pkg/providers/github"
	"github.com/wuwwlwwl/defsec/pkg/providers/google"
	"github.com/wuwwlwwl/defsec/pkg/providers/kubernetes"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud"
	"github.com/wuwwlwwl/defsec/pkg/providers/openstack"
	"github.com/wuwwlwwl/defsec/pkg/providers/oracle"
	"github.com/wuwwlwwl/defsec/pkg/rego/convert"
)

type State struct {
	AWS          aws.AWS
	Azure        azure.Azure
	CloudStack   cloudstack.CloudStack
	DigitalOcean digitalocean.DigitalOcean
	GitHub       github.GitHub
	Google       google.Google
	Kubernetes   kubernetes.Kubernetes
	OpenStack    openstack.OpenStack
	Oracle       oracle.Oracle
	Nifcloud     nifcloud.Nifcloud
}

func (a *State) ToRego() interface{} {
	return convert.StructToRego(reflect.ValueOf(a))
}
