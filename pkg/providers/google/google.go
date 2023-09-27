package google

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/google/bigquery"
	"github.com/wuwwlwwl/defsec/pkg/providers/google/compute"
	"github.com/wuwwlwwl/defsec/pkg/providers/google/dns"
	"github.com/wuwwlwwl/defsec/pkg/providers/google/gke"
	"github.com/wuwwlwwl/defsec/pkg/providers/google/iam"
	"github.com/wuwwlwwl/defsec/pkg/providers/google/kms"
	"github.com/wuwwlwwl/defsec/pkg/providers/google/sql"
	"github.com/wuwwlwwl/defsec/pkg/providers/google/storage"
)

type Google struct {
	BigQuery bigquery.BigQuery
	Compute  compute.Compute
	DNS      dns.DNS
	GKE      gke.GKE
	KMS      kms.KMS
	IAM      iam.IAM
	SQL      sql.SQL
	Storage  storage.Storage
}
