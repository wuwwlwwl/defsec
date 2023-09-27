package container

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/azure/container"
	"github.com/wuwwlwwl/defsec/pkg/scanners/azure"
)

func Adapt(deployment azure.Deployment) container.Container {
	return container.Container{
		KubernetesClusters: adaptKubernetesClusters(deployment),
	}
}

func adaptKubernetesClusters(deployment azure.Deployment) []container.KubernetesCluster {

	return nil
}
