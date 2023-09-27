package ec2

import (
	"github.com/wuwwlwwl/defsec/internal/cidr"
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/framework"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckNoPublicIngressSgr = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0107",
		Aliases:   []string{"aws-vpc-no-public-ingress-sgr"},
		Provider:  providers.AWSProvider,
		Service:   "ec2",
		ShortCode: "no-public-ingress-sgr",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"4.1", "4.2"},
		},
		Summary:     "An ingress security group rule allows traffic from /0.",
		Impact:      "Your port exposed to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressSgrGoodExamples,
			BadExamples:         terraformNoPublicIngressSgrBadExamples,
			Links:               terraformNoPublicIngressSgrLinks,
			RemediationMarkdown: terraformNoPublicIngressSgrRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressSgrGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressSgrBadExamples,
			Links:               cloudFormationNoPublicIngressSgrLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressSgrRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			for _, rule := range group.IngressRules {
				var failed bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						failed = true
						results.Add(
							"Security group rule allows ingress from public internet.",
							block,
						)
					}
				}
				if !failed {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
