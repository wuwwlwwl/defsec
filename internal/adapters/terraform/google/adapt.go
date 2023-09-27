package google

import (
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/bigquery"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/compute"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/dns"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/gke"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/iam"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/kms"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/sql"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/google/storage"
	"github.com/wuwwlwwl/defsec/pkg/providers/google"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) google.Google {
	return google.Google{
		BigQuery: bigquery.Adapt(modules),
		Compute:  compute.Adapt(modules),
		DNS:      dns.Adapt(modules),
		GKE:      gke.Adapt(modules),
		KMS:      kms.Adapt(modules),
		IAM:      iam.Adapt(modules),
		SQL:      sql.Adapt(modules),
		Storage:  storage.Adapt(modules),
	}
}
