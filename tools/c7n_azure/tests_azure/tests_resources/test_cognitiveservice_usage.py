# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import json
from types import SimpleNamespace
from unittest import mock

import requests

import c7n.policy

from c7n.exceptions import PolicyValidationError

from ..azure_common import BaseTest, arm_template


class CognitiveServiceUsageUnitTest(BaseTest):
    parent = {
        'id': '/subscriptions/test/resourceGroups/usage-test/providers/'
        'Microsoft.CognitiveServices/accounts/account-one',
        'name': 'account-one',
        'resourceGroup': 'usage-test',
    }

    def load_usage_policy(self, **data: object) -> c7n.policy.Policy:
        with self.sign_out_patch():
            return self.load_policy(
                {
                    'name': 'test-cognitiveservice-usage',
                    'resource': 'azure.cognitiveservice-usage',
                    **data,
                },
                validate=True,
            )

    @staticmethod
    def usage(name: str, status: str = 'Included', current: int = 0) -> dict:
        return {
            'name': {'value': name, 'localizedValue': name},
            'status': status,
            'currentValue': current,
            'limit': 50,
            'unit': 'Count',
            'quotaPeriod': 'Monthly',
            'nextResetTime': '2026-11-01T00:00:00Z',
        }

    @staticmethod
    def response(payload: dict, status: int = 200) -> requests.Response:
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps(payload).encode()
        return response

    def fake_session(self) -> SimpleNamespace:
        return SimpleNamespace(
            resource_endpoint='https://management.azure.com/',
            cloud_endpoints=SimpleNamespace(
                endpoints=SimpleNamespace(
                    resource_manager='https://management.azure.com/',
                ),
            ),
            credentials=SimpleNamespace(
                get_token=lambda scope: SimpleNamespace(token='test-token'),
            ),
        )

    def test_enumerate_pages_preserves_fields_and_account_identity(self) -> None:
        manager = self.load_usage_policy().resource_manager
        next_url = 'https://management.azure.com/usage-next-page?skiptoken=two'
        responses = [
            self.response(
                {
                    'value': [self.usage('ProvisionedCapacity', 'InOverage', 60)],
                    'nextLink': next_url,
                }
            ),
            self.response({'value': [self.usage('Transactions')]}),
            self.response({'value': [self.usage('ProvisionedCapacity')]}),
        ]
        other_parent = {**self.parent, 'id': self.parent['id'] + '-two'}
        with (
            mock.patch.object(manager, 'get_session', return_value=self.fake_session()),
            mock.patch('c7n_azure.resources.ai_foundry.requests.get', side_effect=responses) as get,
        ):
            rows = manager.enumerate_resources(self.parent, manager.resource_type)
            other_rows = manager.enumerate_resources(other_parent, manager.resource_type)
        self.assertEqual(
            [r['name']['value'] for r in rows], ['ProvisionedCapacity', 'Transactions']
        )
        self.assertEqual(rows[0]['status'], 'InOverage')
        self.assertEqual(rows[0]['currentValue'], 60)
        self.assertEqual(rows[0]['limit'], 50)
        self.assertNotEqual(
            rows[0][manager.resource_type.id], other_rows[0][manager.resource_type.id]
        )
        self.assertNotIn('id', rows[0])
        self.assertEqual(
            get.call_args_list[0].args[0],
            'https://management.azure.com/subscriptions/test/resourceGroups/'
            'usage-test/providers/Microsoft.CognitiveServices/accounts/'
            'account-one/usages',
        )
        self.assertEqual(get.call_args_list[0].kwargs['params'], {'api-version': '2025-06-01'})
        self.assertEqual(get.call_args_list[1].args[0], next_url)
        self.assertIsNone(get.call_args_list[1].kwargs['params'])

    def test_policy_selects_metric_status_and_usage(self) -> None:
        policy = self.load_usage_policy(
            filters=[
                {'type': 'value', 'key': 'name.value', 'op': 'contains', 'value': 'Provisioned'},
                {'type': 'value', 'key': 'status', 'op': 'in', 'value': ['InOverage', 'Blocked']},
                {'type': 'value', 'key': 'currentValue', 'op': 'gt', 'value': 50},
            ]
        )
        manager = policy.resource_manager
        with (
            mock.patch.object(
                manager.get_parent_manager(), 'resources', return_value=[self.parent]
            ),
            mock.patch.object(manager, 'get_session', return_value=self.fake_session()),
            mock.patch(
                'c7n_azure.resources.ai_foundry.requests.get',
                return_value=self.response(
                    {
                        'value': [
                            self.usage('ProvisionedCapacity', 'InOverage', 60),
                            self.usage('ProvisionedThroughput', 'Blocked', 70),
                            self.usage('ProvisionedTokens', 'Included', 60),
                            self.usage('ProvisionedUnits', 'Blocked', 40),
                            self.usage('Transactions', 'Blocked', 70),
                        ]
                    }
                ),
            ),
        ):
            rows = policy.run()
        self.assertEqual(
            [row['name']['value'] for row in rows],
            ['ProvisionedCapacity', 'ProvisionedThroughput'],
        )
        self.assertEqual(rows[0]['c7n:parent-id'], self.parent['id'])

    def test_http_failure_is_not_an_empty_result(self) -> None:
        manager = self.load_usage_policy().resource_manager
        with (
            mock.patch.object(manager, 'get_session', return_value=self.fake_session()),
            mock.patch(
                'c7n_azure.resources.ai_foundry.requests.get',
                return_value=self.response({'error': {}}, 403),
            ),
        ):
            with self.assertRaises(requests.HTTPError):
                manager.enumerate_resources(self.parent, manager.resource_type)

    def test_missing_value_is_not_an_empty_result(self) -> None:
        manager = self.load_usage_policy().resource_manager
        with (
            mock.patch.object(manager, 'get_session', return_value=self.fake_session()),
            mock.patch(
                'c7n_azure.resources.ai_foundry.requests.get', return_value=self.response({})
            ),
        ):
            with self.assertRaises(KeyError):
                manager.enumerate_resources(self.parent, manager.resource_type)

    def test_empty_usages(self) -> None:
        manager = self.load_usage_policy().resource_manager
        with (
            mock.patch.object(manager, 'get_session', return_value=self.fake_session()),
            mock.patch(
                'c7n_azure.resources.ai_foundry.requests.get',
                return_value=self.response({'value': []}),
            ),
        ):
            self.assertEqual(manager.enumerate_resources(self.parent, manager.resource_type), [])

    def test_arm_actions_are_not_available(self) -> None:
        self.load_usage_policy()
        for action in ('delete', 'tag', 'lock'):
            with self.subTest(action=action), self.assertRaises(PolicyValidationError):
                self.load_usage_policy(actions=[{'type': action}])


class CognitiveServiceUsageTest(BaseTest):
    recording_resource_group = 'test_cognitive-service-usage'

    @arm_template('cognitive-service-usage.json')
    def test_usage_fields_and_parent(self) -> None:
        policy = self.load_policy(
            {
                'name': 'cognitiveservice-usage-fields',
                'resource': 'azure.cognitiveservice-usage',
                'filters': [
                    {
                        'type': 'value',
                        'key': 'name.value',
                        'op': 'contains',
                        'value': 'TextAnalytics.',
                    },
                    {'type': 'value', 'key': 'status', 'value': 'Included'},
                    {'type': 'value', 'key': 'currentValue', 'op': 'ge', 'value': 0},
                    {
                        'type': 'parent',
                        'filter': {'resourceGroup': self.recording_resource_group},
                    },
                ],
            },
        )
        parent = policy.resource_manager.get_parent_manager()
        parent.filters.append(
            parent.filter_registry.factory(
                {'resourceGroup': self.recording_resource_group},
                parent,
            )
        )
        rows = policy.run()
        self.assertGreater(len(rows), 0)
        for row in rows:
            self.assertIsInstance(row['name']['value'], str)
            self.assertIsInstance(row['currentValue'], (int, float))
            self.assertIsInstance(row['limit'], (int, float))
            self.assertEqual(row['status'], 'Included')
            self.assertIn(
                '/resourcegroups/test_cognitive-service-usage/',
                row['c7n:parent-id'].lower(),
            )
        self.assertEqual(len({row['c7n:usage-id'] for row in rows}), len(rows))
        negative_filter = policy.resource_manager.filter_registry.factory(
            {'type': 'value', 'key': 'currentValue', 'op': 'lt', 'value': 0},
            policy.resource_manager,
        )
        self.assertEqual(negative_filter.process(rows), [])
