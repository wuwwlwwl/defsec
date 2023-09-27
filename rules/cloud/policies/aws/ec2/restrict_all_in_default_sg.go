package ec2

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/framework"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckRestrictAllInDefaultSG = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0173",
		Provider:  providers.AWSProvider,
		Service:   "ec2",
		ShortCode: "restrict-all-in-default-sg",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"5.3"},
		},
		Summary:    "Default security group should restrict all traffic",
		Impact:     "Easier to accidentally expose resources - goes against principle of least privilege",
		Resolution: "Configure default security group to restrict all traffic",
		Explanation: `
Configuring all VPC default security groups to restrict all traffic will encourage least
privilege security group development and mindful placement of AWS resources into
security groups which will in-turn reduce the exposure of those resources.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/default-custom-security-groups.html",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, vpc := range s.AWS.EC2.VPCs {
			for _, sg := range vpc.SecurityGroups {
				if sg.IsDefault.IsTrue() {
					if len(sg.IngressRules) > 0 || len(sg.EgressRules) > 0 {
						results.Add(
							"Default security group for VPC has ingress or egress rules.",
							&vpc,
						)
					}
				} else {
					results.AddPassed(&vpc)
				}
			}
		}
		return
	},
)
