package compute

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0039",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "SSL policies should enforce secure versions of TLS",
		Impact:      "Data in transit is not sufficiently secured",
		Resolution:  "Enforce a minimum TLS version of 1.2",
		Explanation: `TLS versions prior to 1.2 are outdated and insecure. You should use 1.2 as aminimum version.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, policy := range s.Google.Compute.SSLPolicies {
			if policy.Metadata.IsUnmanaged() {
				continue
			}
			if policy.MinimumTLSVersion.NotEqualTo("TLS_1_2") {
				results.Add(
					"TLS policy does not specify a minimum of TLS 1.2",
					policy.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&policy)
			}
		}
		return
	},
)
