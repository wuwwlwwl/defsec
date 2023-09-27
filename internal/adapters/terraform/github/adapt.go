package github

import (
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/github/branch_protections"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/github/repositories"
	"github.com/wuwwlwwl/defsec/internal/adapters/terraform/github/secrets"
	"github.com/wuwwlwwl/defsec/pkg/providers/github"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) github.GitHub {
	return github.GitHub{
		Repositories:       repositories.Adapt(modules),
		EnvironmentSecrets: secrets.Adapt(modules),
		BranchProtections:  branch_protections.Adapt(modules),
	}
}
