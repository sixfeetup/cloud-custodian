# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from ..azure_common import BaseTest, arm_template, cassette_name


# See ../templates/cost-management-scheduled-action.md for how to provision
# the resource and record cassettes for this test class - it deviates from
# the provision.sh/cleanup.sh convention documented in ../templates/readme.md.
class CostManagementScheduledActionTest(BaseTest):

    def test_schema_validate(self):
        p = self.load_policy({
            'name': 'cost-management-scheduled-action-schema',
            'resource': 'azure.cost-management-scheduled-action',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'value': 'cctestscheduledaction'
                }
            ]
        }, validate=True)
        self.assertTrue(p)

    @arm_template('cost-management-scheduled-action.json')
    @cassette_name('common')
    def test_resource(self):
        p = self.load_policy({
            'name': 'cost-management-scheduled-action',
            'resource': 'azure.cost-management-scheduled-action',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'value': 'cctestscheduledaction'
                }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['kind'], 'InsightAlert')

    @arm_template('cost-management-scheduled-action.json')
    @cassette_name('healthy-alert')
    def test_healthy_anomaly_alert_not_flagged(self):
        # cctestscheduledaction is Enabled, Daily, with a recipient - it
        # should not be flagged by the benchmark's unhealthy-alert filter.
        p = self.load_policy({
            'name': 'cost-management-scheduled-action-unhealthy',
            'resource': 'azure.cost-management-scheduled-action',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'value': 'cctestscheduledaction'
                },
                {'or': [
                    {'type': 'value', 'key': 'properties.status', 'op': 'ne', 'value': 'Enabled'},
                    {'type': 'value', 'key': 'properties.schedule.frequency',
                     'op': 'ne', 'value': 'Daily'},
                    {'type': 'value', 'key': 'properties.notification.to', 'value': 'absent'},
                ]}
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 0)
