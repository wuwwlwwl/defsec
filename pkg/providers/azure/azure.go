package azure

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/appservice"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/authorization"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/compute"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/container"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/database"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/datafactory"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/datalake"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/keyvault"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/monitor"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/network"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/securitycenter"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/storage"
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/synapse"
)

type Azure struct {
	AppService     appservice.AppService
	Authorization  authorization.Authorization
	Compute        compute.Compute
	Container      container.Container
	Database       database.Database
	DataFactory    datafactory.DataFactory
	DataLake       datalake.DataLake
	KeyVault       keyvault.KeyVault
	Monitor        monitor.Monitor
	Network        network.Network
	SecurityCenter securitycenter.SecurityCenter
	Storage        storage.Storage
	Synapse        synapse.Synapse
}
