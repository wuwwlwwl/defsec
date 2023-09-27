package dns

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/dns"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		Records: adaptRecords(modules),
	}
}
