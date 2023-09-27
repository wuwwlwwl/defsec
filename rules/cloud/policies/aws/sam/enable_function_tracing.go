package sam

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/providers"
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/sam"
	"github.com/wuwwlwwl/defsec/pkg/scan"
	"github.com/wuwwlwwl/defsec/pkg/severity"
	"github.com/wuwwlwwl/defsec/pkg/state"
)

var CheckEnableFunctionTracing = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0125",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-function-tracing",
		Summary:     "SAM Function must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of the function.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-tracing",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableFunctionTracingGoodExamples,
			BadExamples:         cloudFormationEnableFunctionTracingBadExamples,
			Links:               cloudFormationEnableFunctionTracingLinks,
			RemediationMarkdown: cloudFormationEnableFunctionTracingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, function := range s.AWS.SAM.Functions {
			if function.Metadata.IsUnmanaged() {
				continue
			}

			if function.Tracing.NotEqualTo(sam.TracingModeActive) {
				results.Add(
					"X-Ray tracing is not enabled,",
					function.Tracing,
				)
			} else {
				results.AddPassed(&function)
			}
		}
		return
	},
)
