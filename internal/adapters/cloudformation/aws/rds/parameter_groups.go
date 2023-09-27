package rds

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/rds"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation/parser"
	"github.com/wuwwlwwl/defsec/pkg/types"
)

func getParameterGroups(ctx parser.FileContext) (parametergroups []rds.ParameterGroups) {

	for _, r := range ctx.GetResourcesByType("AWS::RDS::DBParameterGroup") {

		paramgroup := rds.ParameterGroups{
			Metadata:               r.Metadata(),
			DBParameterGroupName:   r.GetStringProperty("DBParameterGroupName"),
			DBParameterGroupFamily: r.GetStringProperty("DBParameterGroupFamily"),
			Parameters:             getParameters(r),
		}

		parametergroups = append(parametergroups, paramgroup)
	}

	return parametergroups
}

func getParameters(r *parser.Resource) (parameters []rds.Parameters) {

	dBParam := r.GetProperty("Parameters")

	if dBParam.IsNil() || dBParam.IsNotList() {
		return parameters
	}

	for _, dbp := range dBParam.AsList() {
		parameters = append(parameters, rds.Parameters{
			Metadata:       dbp.Metadata(),
			ParameterName:  types.StringDefault("", dbp.Metadata()),
			ParameterValue: types.StringDefault("", dbp.Metadata()),
		})
	}
	return parameters
}
