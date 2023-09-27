package neptune

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckEnableStorageEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0076",
		Provider:    providers.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-storage-encryption",
		Summary:     "Neptune storage must be encrypted at rest",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable encryption of Neptune storage",
		Explanation: `Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableStorageEncryptionGoodExamples,
			BadExamples:         terraformEnableStorageEncryptionBadExamples,
			Links:               terraformEnableStorageEncryptionLinks,
			RemediationMarkdown: terraformEnableStorageEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableStorageEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableStorageEncryptionBadExamples,
			Links:               cloudFormationEnableStorageEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableStorageEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.StorageEncrypted.IsFalse() {
				results.Add(
					"Cluster does not have storage encryption enabled.",
					cluster.StorageEncrypted,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
