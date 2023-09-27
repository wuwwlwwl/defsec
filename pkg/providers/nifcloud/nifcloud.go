package nifcloud

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/computing"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/dns"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/nas"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/network"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/rdb"
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/sslcertificate"
)

type Nifcloud struct {
	Computing      computing.Computing
	DNS            dns.DNS
	NAS            nas.NAS
	Network        network.Network
	RDB            rdb.RDB
	SSLCertificate sslcertificate.SSLCertificate
}
