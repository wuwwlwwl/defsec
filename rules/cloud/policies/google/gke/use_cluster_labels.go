package gke

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckUseClusterLabels = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0051",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-cluster-labels",
		Summary:     "Clusters should be configured with Labels",
		Impact:      "Asset management can be limited/more difficult",
		Resolution:  "Set cluster resource labels",
		Explanation: `Labels make it easier to manage assets and differentiate between clusters and environments, allowing the mapping of computational resources to the wider organisational structure.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseClusterLabelsGoodExamples,
			BadExamples:         terraformUseClusterLabelsBadExamples,
			Links:               terraformUseClusterLabelsLinks,
			RemediationMarkdown: terraformUseClusterLabelsRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.ResourceLabels.Len() == 0 {
				results.Add(
					"Cluster does not use GCE resource labels.",
					cluster.ResourceLabels,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
