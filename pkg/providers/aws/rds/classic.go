package rds

import (
	"github.com/wuwwlwwl/defsec/pkg/types"
)

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	Metadata types.Metadata
}
