package github

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type BranchProtection struct {
	Metadata             defsecTypes.Metadata
	RequireSignedCommits defsecTypes.BoolValue
}

func (b BranchProtection) RequiresSignedCommits() bool {
	return b.RequireSignedCommits.IsTrue()
}
