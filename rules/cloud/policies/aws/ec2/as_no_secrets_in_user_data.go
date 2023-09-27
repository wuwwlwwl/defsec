package ec2

import (
	"fmt"

	"github.com/wuwwlwwl/defsec/pkg/severity"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/wuwwlwwl/defsec/internal/rules"

	"github.com/wuwwlwwl/defsec/pkg/providers"

	"github.com/owenrumney/squealer/pkg/squealer"
)

var scanner = squealer.NewStringScanner()

var CheckASNoSecretsInUserData = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0129",
		Aliases:     []string{"aws-autoscaling-no-secrets-in-user-data"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-secrets-in-launch-template-user-data",
		Summary:     "User data for EC2 instances must not contain sensitive AWS keys",
		Impact:      "User data is visible through the AWS Management console",
		Resolution:  "Remove sensitive data from the EC2 instance user-data generated by launch templates",
		Explanation: `EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformASNoSecretsInUserDataGoodExamples,
			BadExamples:         terraformASNoSecretsInUserDataBadExamples,
			Links:               terraformASNoSecretsInUserDataLinks,
			RemediationMarkdown: terraformASNoSecretsInUserDataRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationASNoSecretsInUserDataGoodExamples,
			BadExamples:         cloudFormationASNoSecretsInUserDataBadExamples,
			Links:               cloudFormationASNoSecretsInUserDataLinks,
			RemediationMarkdown: cloudFormationASNoSecretsInUserDataRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.AWS.EC2.LaunchTemplates {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if result := scanner.Scan(instance.UserData.Value()); result.TransgressionFound {
				results.Add(
					fmt.Sprintf("Sensitive data found in launch template user data: %s", result.Description),
					instance.UserData,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
