package iam

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/framework"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckRequireNumbersInPasswords = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0059",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "require-numbers-in-passwords",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"1.8"},
		},
		Summary:     "IAM Password policy should have requirement for at least one number in the password.",
		Impact:      "Short, simple passwords are easier to compromise",
		Resolution:  "Enforce longer, more complex passwords in the policy",
		Explanation: `IAM account password policies should ensure that passwords content including at least one number.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireNumbersInPasswordsGoodExamples,
			BadExamples:         terraformRequireNumbersInPasswordsBadExamples,
			Links:               terraformRequireNumbersInPasswordsLinks,
			RemediationMarkdown: terraformRequireNumbersInPasswordsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.Metadata.IsUnmanaged() {
			return
		}

		if policy.RequireNumbers.IsFalse() {
			results.Add(
				"Password policy does not require numbers.",
				policy.RequireNumbers,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
