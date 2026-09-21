# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from ..azure_common import BaseTest


class VnetTest(BaseTest):
    def test_vnet_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-azure-vnet',
                'resource': 'azure.vnet'
            }, validate=True)
            self.assertTrue(p)


class VnetFlowLogsFilterTest(BaseTest):
    def test_flow_log_filter_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-azure-vnet',
                'resource': 'azure.vnet',
                'filters': [
                    {
                        'or': [
                            {
                                'type': 'flow-logs',
                                'key': 'logs',
                                'value': 'empty'
                            },
                            {
                                'and': [
                                    {
                                        'type': 'flow-logs',
                                        'key': 'logs[0].retentionPolicy.days',
                                        'op': 'ne',
                                        'value': 0
                                    },
                                    {
                                        'type': 'flow-logs',
                                        'key': 'logs[0].retentionPolicy.days',
                                        'op': 'lt',
                                        'value': 90
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_flow_log_filter_no_logs(self):
        p = self.load_policy({
            'name': 'test-azure-vnet',
            'resource': 'azure.vnet',
            'filters': [
                {
                    'type': 'flow-logs',
                    'key': 'length(logs)',
                    'value': 0
                }
            ]
        })

        resources = p.run()
        self.assertEqual(len(resources), 0)

    def test_flow_log_filter_matching(self):
        p = self.load_policy({
            'name': 'test-azure-vnet',
            'resource': 'azure.vnet',
            'filters': [
                {
                    'type': 'flow-logs',
                    'key': 'length(logs)',
                    'op': 'gt',
                    'value': 0
                }
            ]
        })

        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_flow_log_filter_retention_below_90_days(self):
        p = self.load_policy({
            'name': 'test-azure-vnet',
            'resource': 'azure.vnet',
            'filters': [
                {
                    'or': [
                        {
                            'type': 'flow-logs',
                            'key': 'logs',
                            'value': 'empty'
                        },
                        {
                            'and': [
                                {
                                    'type': 'flow-logs',
                                    'key': 'logs[0].retentionPolicy.days',
                                    'op': 'ne',
                                    'value': 0
                                },
                                {
                                    'type': 'flow-logs',
                                    'key': 'logs[0].retentionPolicy.days',
                                    'op': 'lt',
                                    'value': 90
                                }
                            ]
                        }
                    ]
                }
            ]
        })

        resources = p.run()
        self.assertEqual(len(resources), 0)
