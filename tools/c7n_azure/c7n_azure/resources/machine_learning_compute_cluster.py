# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ChildArmResourceManager


WORKSPACE_DISCOVERY_URL = 'c7n:WorkspaceDiscoveryUrl'


@resources.register('machine-learning-compute-cluster')
class MachineLearningComputeCluster(ChildArmResourceManager):

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        service = 'azure.mgmt.machinelearningservices'
        client = 'MachineLearningServicesMgmtClient'
        enum_spec = ('compute', 'list', None)
        parent_manager_name = 'machine-learning-workspace'
        resource_type = 'Microsoft.MachineLearningServices/workspaces/computes'
        default_report_fields = (
            'name',
            'resourceGroup',
            '"c7n:parent-id"',
            'properties.properties.currentNodeCount',
            'properties.properties.nodeStateCounts.runningNodeCount',
            'properties.properties.scaleSettings.minNodeCount',
            'properties.properties.scaleSettings.maxNodeCount',
        )

        @classmethod
        def extra_args(cls, parent_resource):
            return {
                'resource_group_name': parent_resource['resourceGroup'],
                'workspace_name': parent_resource['name'],
            }

    def enumerate_resources(self, parent_resource, type_info, vault_url=None, **params):
        resources = super().enumerate_resources(
            parent_resource,
            type_info,
            vault_url=vault_url,
            **params,
        )
        clusters = [
            resource for resource in resources
            if resource['properties']['computeType'] == 'AmlCompute'
        ]
        for cluster in clusters:
            cluster[WORKSPACE_DISCOVERY_URL] = (
                parent_resource['properties']['discoveryUrl']
            )
        return clusters
