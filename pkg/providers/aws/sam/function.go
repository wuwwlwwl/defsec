package sam

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type Function struct {
	Metadata        defsecTypes.Metadata
	FunctionName    defsecTypes.StringValue
	Tracing         defsecTypes.StringValue
	ManagedPolicies []defsecTypes.StringValue
	Policies        []iam.Policy
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	Metadata  defsecTypes.Metadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
