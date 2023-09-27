package nifcloud

import (
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/nifcloud/computing"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/nifcloud/dns"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/nifcloud/nas"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/nifcloud/network"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/nifcloud/rdb"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/nifcloud/sslcertificate"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) nifcloud.Nifcloud {
	return nifcloud.Nifcloud{
		Computing:      computing.Adapt(modules),
		DNS:            dns.Adapt(modules),
		NAS:            nas.Adapt(modules),
		Network:        network.Adapt(modules),
		RDB:            rdb.Adapt(modules),
		SSLCertificate: sslcertificate.Adapt(modules),
	}
}
