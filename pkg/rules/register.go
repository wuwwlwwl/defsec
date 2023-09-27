package rules

import (
	"github.com/wuwwlwwl/defsec/internal/rules"
	"github.com/wuwwlwwl/defsec/pkg/framework"
	"github.com/wuwwlwwl/defsec/pkg/scan"
)

func Register(rule scan.Rule, f scan.CheckFunc) rules.RegisteredRule {
	return rules.Register(rule, f)
}

func GetRegistered(fw ...framework.Framework) (registered []rules.RegisteredRule) {
	return rules.GetFrameworkRules(fw...)
}
