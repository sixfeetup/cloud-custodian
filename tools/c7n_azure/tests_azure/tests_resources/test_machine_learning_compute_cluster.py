# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import datetime
from unittest.mock import Mock

from azure.mgmt.machinelearningservices.models import (
    AmlCompute,
    AmlComputeProperties,
    ComputeInstance,
    ComputeInstanceProperties,
    ComputeResource,
    NodeStateCounts,
    ScaleSettings,
)

from ..azure_common import BaseTest


class MachineLearningComputeClusterTest(BaseTest):

    def test_machine_learning_compute_cluster_schema_validate(self):
        p = self.load_policy({
            'name': 'machine-learning-compute-clusters',
            'resource': 'azure.machine-learning-compute-cluster',
        }, validate=True)
        self.assertTrue(p)

    def test_machine_learning_compute_cluster_child_query(self):
        parent_id = (
            '/subscriptions/ea42f556-5106-4743-99b0-c129bfa71a47/'
            'resourceGroups/test-rg/providers/Microsoft.MachineLearningServices/'
            'workspaces/test-workspace'
        )
        cluster_properties = AmlComputeProperties(
            vm_size='Standard_DS2_v2',
            scale_settings=ScaleSettings(
                max_node_count=4,
                min_node_count=1,
                node_idle_time_before_scale_down=datetime.timedelta(minutes=5),
            ),
        )
        cluster_properties.current_node_count = 2
        cluster_properties.node_state_counts = NodeStateCounts()
        cluster_properties.node_state_counts.running_node_count = 1
        cluster = ComputeResource(
            properties=AmlCompute(properties=cluster_properties),
            location='westus',
        )
        cluster.id = f'{parent_id}/computes/test-cluster'
        cluster.name = 'test-cluster'
        cluster.type = 'Microsoft.MachineLearningServices/workspaces/computes'

        instance = ComputeResource(
            properties=ComputeInstance(
                properties=ComputeInstanceProperties(vm_size='Standard_DS2_v2'),
            ),
            location='westus',
        )
        instance.id = f'{parent_id}/computes/test-instance'
        instance.name = 'test-instance'
        instance.type = 'Microsoft.MachineLearningServices/workspaces/computes'

        parent_manager = Mock()
        parent_manager.resource_type.id = 'id'
        parent_manager.resources.return_value = [{
            'id': parent_id,
            'name': 'test-workspace',
            'resourceGroup': 'test-rg',
            'properties': {
                'discoveryUrl': 'https://westus.api.azureml.ms/discovery',
            },
        }]

        client = Mock()
        client.compute.list.return_value = [cluster, instance]

        p = self.load_policy({
            'name': 'machine-learning-compute-clusters',
            'resource': 'azure.machine-learning-compute-cluster',
        })
        manager = p.resource_manager
        manager.get_parent_manager = Mock(return_value=parent_manager)
        manager.get_client = Mock(return_value=client)

        resources = manager.resources()

        client.compute.list.assert_called_once_with(
            resource_group_name='test-rg',
            workspace_name='test-workspace',
        )
        self.assertEqual(['test-cluster'], [r['name'] for r in resources])
        self.assertEqual(parent_id, resources[0]['c7n:parent-id'])
        self.assertEqual(
            'https://westus.api.azureml.ms/discovery',
            resources[0]['c7n:WorkspaceDiscoveryUrl'],
        )
        properties = resources[0]['properties']['properties']
        self.assertEqual(2, properties['currentNodeCount'])
        self.assertEqual(1, properties['nodeStateCounts']['runningNodeCount'])
        self.assertEqual(1, properties['scaleSettings']['minNodeCount'])
        self.assertEqual(4, properties['scaleSettings']['maxNodeCount'])
