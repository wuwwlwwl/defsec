package datalake

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0036",
		Provider:    providers.AzureProvider,
		Service:     "datalake",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Unencrypted data lake storage.",
		Impact:      "Data could be read if compromised",
		Resolution:  "Enable encryption of data lake storage",
		Explanation: `Datalake storage encryption defaults to Enabled, it shouldn't be overridden to Disabled.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, store := range s.Azure.DataLake.Stores {
			if store.EnableEncryption.IsFalse() {
				results.Add(
					"Data lake store is not encrypted.",
					store.EnableEncryption,
				)
			} else {
				results.AddPassed(&store)
			}
		}
		return
	},
)
