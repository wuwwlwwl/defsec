package sslcertificate

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/sslcertificate"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) sslcertificate.SSLCertificate {
	return sslcertificate.SSLCertificate{
		ServerCertificates: adaptServerCertificates(modules),
	}
}
