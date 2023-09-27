package rdb

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/nifcloud/rdb"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) rdb.RDB {
	return rdb.RDB{
		DBSecurityGroups: adaptDBSecurityGroups(modules),
		DBInstances:      adaptDBInstances(modules),
	}
}
