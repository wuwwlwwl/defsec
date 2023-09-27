package github

import (
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

type Repository struct {
	Metadata            defsecTypes.Metadata
	Public              defsecTypes.BoolValue
	VulnerabilityAlerts defsecTypes.BoolValue
	Archived            defsecTypes.BoolValue
}

func (r Repository) IsArchived() bool {
	return r.Archived.IsTrue()
}
