package sam

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type StateMachine struct {
	Metadata             defsecTypes.Metadata
	Name                 defsecTypes.StringValue
	LoggingConfiguration LoggingConfiguration
	ManagedPolicies      []defsecTypes.StringValue
	Policies             []iam.Policy
	Tracing              TracingConfiguration
}

type LoggingConfiguration struct {
	Metadata       defsecTypes.Metadata
	LoggingEnabled defsecTypes.BoolValue
}

type TracingConfiguration struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}
