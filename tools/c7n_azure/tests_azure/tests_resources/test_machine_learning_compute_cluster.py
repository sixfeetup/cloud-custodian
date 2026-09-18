# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import datetime
from unittest.mock import call, Mock, patch

from azure.mgmt.machinelearningservices.models import (
    AmlCompute,
    AmlComputeProperties,
    ComputeInstance,
    ComputeInstanceProperties,
    ComputeResource,
    NodeStateCounts,
    ScaleSettings,
)

from c7n.exceptions import PolicyValidationError

from ..azure_common import BaseTest


class MachineLearningComputeClusterTest(BaseTest):

    parent_id = (
        '/subscriptions/ea42f556-5106-4743-99b0-c129bfa71a47/'
        'resourceGroups/test-rg/providers/Microsoft.MachineLearningServices/'
        'workspaces/test-workspace'
    )

    def _load_inactive_filter(self, since='1d'):
        policy = self.load_policy({
            'name': 'inactive-machine-learning-compute-clusters',
            'resource': 'azure.machine-learning-compute-cluster',
            'filters': [{
                'type': 'inactive',
                'since': since,
            }],
        })
        return policy.resource_manager.filters[0]

    def _cluster(
        self,
        name,
        running_node_count=0,
        parent_id=None,
        discovery_url='https://westus.api.azureml.ms/discovery',
    ):
        return {
            'name': name,
            'c7n:parent-id': parent_id or self.parent_id,
            'c7n:WorkspaceDiscoveryUrl': discovery_url,
            'properties': {
                'properties': {
                    'nodeStateCounts': {
                        'runningNodeCount': running_node_count,
                    },
                },
            },
        }

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

    def test_inactive_schema_validate(self):
        policy = self.load_policy({
            'name': 'inactive-machine-learning-compute-clusters',
            'resource': 'azure.machine-learning-compute-cluster',
            'filters': [{
                'type': 'inactive',
                'since': '1d',
            }],
        }, validate=True)

        self.assertTrue(policy)

    def test_inactive_schema_rejects_invalid_values(self):
        for inactive_filter in (
            {'type': 'inactive'},
            {'type': 'inactive', 'since': '0d'},
            {'type': 'inactive', 'since': '-1d'},
            {'type': 'inactive', 'since': '1y'},
            {'type': 'inactive', 'since': '1d', 'state': 'idle'},
        ):
            with self.subTest(inactive_filter=inactive_filter):
                with self.assertRaises(PolicyValidationError):
                    self.load_policy({
                        'name': 'inactive-machine-learning-compute-clusters',
                        'resource': 'azure.machine-learning-compute-cluster',
                        'filters': [inactive_filter],
                    }, validate=True)

    def test_inactive_short_circuit_running_clusters(self):
        inactive_filter = self._load_inactive_filter()
        inactive_filter._get_active_targets = Mock(return_value=set())
        clusters = [
            self._cluster('running-cluster', running_node_count=1),
            self._cluster('idle-cluster'),
        ]

        resources = inactive_filter.process(clusters)

        self.assertEqual(['idle-cluster'], [r['name'] for r in resources])
        inactive_filter._get_active_targets.assert_called_once()

    def test_inactive_short_circuit_skips_history_for_running_clusters(self):
        inactive_filter = self._load_inactive_filter()
        inactive_filter._get_active_targets = Mock(return_value=set())

        resources = inactive_filter.process([
            self._cluster('running-cluster', running_node_count=1),
        ])

        self.assertEqual([], resources)
        inactive_filter._get_active_targets.assert_not_called()

    @patch(
        'c7n_azure.resources.machine_learning_compute_cluster.requests.post',
    )
    def test_inactive_history_pagination(self, post):
        inactive_filter = self._load_inactive_filter()
        session = Mock()
        session.credentials.get_token.return_value.token = 'test-token'
        inactive_filter.manager.get_session = Mock(return_value=session)
        first_response = Mock()
        first_response.json.return_value = {
            'value': [{'experimentId': 'first'}],
            'continuationToken': 'next-page',
        }
        second_response = Mock()
        second_response.json.return_value = {
            'value': [{'experimentId': 'second'}],
            'continuationToken': None,
        }
        post.side_effect = [first_response, second_response]
        url = 'https://westus.api.azureml.ms/history/v1.0/experiments:query'

        values = inactive_filter._query_history(
            url,
            {'viewType': 'ActiveOnly'},
        )

        self.assertEqual(
            [{'experimentId': 'first'}, {'experimentId': 'second'}],
            values,
        )
        session._initialize_session.assert_called_once_with()
        session.credentials.get_token.assert_called_once_with(
            'https://ml.azure.com/.default',
        )
        self.assertEqual(2, post.call_count)
        self.assertEqual(
            {'api-version': '2023-10-01'},
            post.call_args_list[0].kwargs['params'],
        )
        self.assertEqual(
            {'viewType': 'ActiveOnly'},
            post.call_args_list[0].kwargs['json'],
        )
        self.assertEqual(
            {
                'viewType': 'ActiveOnly',
                'continuationToken': 'next-page',
            },
            post.call_args_list[1].kwargs['json'],
        )
        for post_call in post.call_args_list:
            self.assertEqual(30, post_call.kwargs['timeout'])
            self.assertEqual(
                {
                    'Authorization': 'Bearer test-token',
                    'Content-Type': 'application/json',
                },
                post_call.kwargs['headers'],
            )
        first_response.raise_for_status.assert_called_once_with()
        second_response.raise_for_status.assert_called_once_with()

    @patch(
        'c7n_azure.resources.machine_learning_compute_cluster.requests.post',
    )
    def test_inactive_history_pagination_rejects_missing_value(self, post):
        inactive_filter = self._load_inactive_filter()
        session = Mock()
        session.credentials.get_token.return_value.token = 'test-token'
        inactive_filter.manager.get_session = Mock(return_value=session)
        response = Mock()
        response.json.return_value = {}
        post.return_value = response

        with self.assertRaises(TypeError):
            inactive_filter._query_history(
                'https://westus.api.azureml.ms/history/v1.0/experiments:query',
                {'viewType': 'ActiveOnly'},
            )

        response.raise_for_status.assert_called_once_with()

    def test_inactive_experiments_include_recent_archived(self):
        inactive_filter = self._load_inactive_filter()
        inactive_filter._query_history = Mock(side_effect=[
            [
                {'experimentId': 'active'},
                {'experimentId': 'shared'},
                {'experimentId': ''},
            ],
            [
                {'experimentId': 'shared'},
                {'experimentId': 'archived'},
            ],
        ])
        cutoff = datetime.datetime(
            2024,
            1,
            2,
            3,
            4,
            5,
            tzinfo=datetime.timezone.utc,
        )

        experiments = inactive_filter._get_experiments(
            self._cluster('cluster'),
            cutoff,
        )

        self.assertEqual(['active', 'shared', 'archived'], experiments)
        url = (
            f'https://westus.api.azureml.ms/history/v1.0{self.parent_id}/'
            'experiments:query'
        )
        self.assertEqual(
            [
                call(url, {'viewType': 'ActiveOnly'}),
                call(
                    url,
                    {
                        'viewType': 'ArchivedOnly',
                        'filter': 'archivedTime ge 2024-01-02T03:04:05Z',
                    },
                ),
            ],
            inactive_filter._query_history.call_args_list,
        )

    def test_inactive_active_targets_include_standalone_and_pipeline_runs(self):
        inactive_filter = self._load_inactive_filter()
        inactive_filter._get_experiments = Mock(
            return_value=['experiment-one', 'experiment-two'],
        )
        inactive_filter._query_history = Mock(side_effect=[
            [
                {'runId': 'standalone', 'target': 'Cluster-One'},
                {'runId': 'pipeline-parent', 'target': None},
            ],
            [{'runId': 'pipeline-child', 'target': 'CLUSTER-TWO'}],
            [{'runId': 'second-standalone', 'target': 'Cluster-Three'}],
            [{'runId': 'targetless', 'target': ''}],
        ])
        cutoff = datetime.datetime(
            2024,
            1,
            2,
            3,
            4,
            5,
            tzinfo=datetime.timezone.utc,
        )

        targets = inactive_filter._get_active_targets(
            [self._cluster('cluster')],
            cutoff,
        )

        self.assertEqual(
            {'cluster-one', 'cluster-two', 'cluster-three'},
            targets,
        )
        statuses = (
            'NotStarted',
            'Starting',
            'Provisioning',
            'Preparing',
            'Queued',
            'Running',
            'Finalizing',
            'CancelRequested',
            'NotResponding',
        )
        status_filter = ' or '.join(
            f"status eq '{status}'" for status in statuses
        )
        base_url = (
            f'https://westus.api.azureml.ms/history/v1.0{self.parent_id}/'
            'experimentids'
        )
        self.assertEqual(
            [
                call(
                    f'{base_url}/experiment-one/runs:query',
                    {'filter': status_filter},
                ),
                call(
                    f'{base_url}/experiment-one/runs:query',
                    {'filter': 'endTimeUtc ge 2024-01-02T03:04:05Z'},
                ),
                call(
                    f'{base_url}/experiment-two/runs:query',
                    {'filter': status_filter},
                ),
                call(
                    f'{base_url}/experiment-two/runs:query',
                    {'filter': 'endTimeUtc ge 2024-01-02T03:04:05Z'},
                ),
            ],
            inactive_filter._query_history.call_args_list,
        )

    def test_inactive_workspace_cache(self):
        inactive_filter = self._load_inactive_filter()
        inactive_filter._get_active_targets = Mock(side_effect=[
            {'active-west'},
            {'active-east'},
        ])
        east_parent_id = self.parent_id.replace(
            'test-workspace',
            'east-workspace',
        )
        clusters = [
            self._cluster('active-west'),
            self._cluster('idle-west'),
            self._cluster(
                'active-east',
                parent_id=east_parent_id,
                discovery_url='https://eastus.api.azureml.ms/discovery',
            ),
        ]

        resources = inactive_filter.process(clusters)

        self.assertEqual(['idle-west'], [r['name'] for r in resources])
        self.assertEqual(2, inactive_filter._get_active_targets.call_count)
        history_calls = inactive_filter._get_active_targets.call_args_list
        west_resources = history_calls[0].args[0]
        east_resources = history_calls[1].args[0]
        self.assertEqual(
            ['active-west', 'idle-west'],
            [r['name'] for r in west_resources],
        )
        self.assertEqual(['active-east'], [r['name'] for r in east_resources])

    def test_inactive_active_targets_use_separate_workspace_endpoints(self):
        inactive_filter = self._load_inactive_filter()
        inactive_filter._get_experiments = Mock(side_effect=[
            ['west-experiment'],
            ['east-experiment'],
        ])
        inactive_filter._query_history = Mock(side_effect=[
            [{'target': 'west-cluster'}],
            [],
            [{'target': 'east-cluster'}],
            [],
        ])
        cutoff = datetime.datetime(
            2024,
            1,
            2,
            3,
            4,
            5,
            tzinfo=datetime.timezone.utc,
        )
        east_parent_id = self.parent_id.replace(
            'test-workspace',
            'east-workspace',
        )

        west_targets = inactive_filter._get_active_targets(
            [self._cluster('west-cluster')],
            cutoff,
        )
        east_targets = inactive_filter._get_active_targets(
            [self._cluster(
                'east-cluster',
                parent_id=east_parent_id,
                discovery_url='https://eastus.api.azureml.ms/discovery',
            )],
            cutoff,
        )

        self.assertEqual({'west-cluster'}, west_targets)
        self.assertEqual({'east-cluster'}, east_targets)
        urls = [
            history_call.args[0]
            for history_call in inactive_filter._query_history.call_args_list
        ]
        self.assertTrue(all(
            url.startswith('https://westus.api.azureml.ms/')
            for url in urls[:2]
        ))
        self.assertTrue(all(
            url.startswith('https://eastus.api.azureml.ms/')
            for url in urls[2:]
        ))
