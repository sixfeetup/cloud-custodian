# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

from azure.core.exceptions import ResourceNotFoundError

from c7n.utils import local_session
from c7n_azure.query import _serialize
from c7n_azure.resources.machine_learning_job import (
    MachineLearningJob,
    MachineLearningJobArchiveAction,
)
from c7n_azure.session import Session
from c7n_azure.utils import ResourceIdParser
from ..azure_common import BaseTest, arm_template, cassette_name


class MachineLearningJobTest(BaseTest):

    def test_machine_learning_job_schema_validate(self):
        p = self.load_policy({
            'name': 'find-all-machine-learning-jobs',
            'resource': 'azure.machine-learning-job'
        }, validate=True)
        self.assertTrue(p)

        p = self.load_policy({
            'name': 'archive-machine-learning-jobs',
            'resource': 'azure.machine-learning-job',
            'actions': [{'type': 'archive'}],
        }, validate=True)
        self.assertTrue(p)

        for action in ('tag', 'untag', 'auto-tag-user', 'auto-tag-date',
                       'tag-trim', 'mark-for-op'):
            self.assertNotIn(action, MachineLearningJob.action_registry)
        self.assertNotIn('marked-for-op', MachineLearningJob.filter_registry)
        self.assertNotIn('location', MachineLearningJob.resource_type.default_report_fields)

    @arm_template('machine-learning-job.json')
    @cassette_name('machine-learning-jobs')
    def test_machine_learning_job_query(self):
        p = self.load_policy({
            'name': 'find-all-machine-learning-jobs',
            'resource': 'azure.machine-learning-job',
        })
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual('cctest-sweep-job', resources[0]['name'])
        self.assertIn('/jobs/', resources[0]['id'])

    @arm_template('machine-learning-job.json')
    @cassette_name('machine-learning-jobs')
    def test_machine_learning_job_filter_sweep_parallelism(self):
        p = self.load_policy({
            'name': 'ml-sweep-jobs-over-parallelism-limit',
            'resource': 'azure.machine-learning-job',
            'filters': [{
                'type': 'value',
                'key': 'properties.jobType',
                'value': 'Sweep'
            }, {
                'type': 'value',
                'key': 'properties.limits.maxConcurrentTrials',
                'op': 'gt',
                'value': 10
            }],
        })
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual('cctest-sweep-job', resources[0]['name'])

    @arm_template('machine-learning-job-archive.json')
    @cassette_name('machine-learning-job-archive')
    def test_machine_learning_job_archive(self):
        p = self.load_policy({
            'name': 'archive-machine-learning-job',
            'resource': 'azure.machine-learning-job',
            'filters': [{
                'type': 'value',
                'key': 'resourceGroup',
                'value': 'test_machine-learning-job-archive',
            }, {
                'type': 'value',
                'key': 'name',
                'value': 'cctest-archive-job',
            }, {
                'type': 'value',
                'key': 'properties.status',
                'value': 'Completed',
            }, {
                'type': 'value',
                'key': 'properties.isArchived',
                'op': 'ne',
                'value': True,
            }],
            'actions': [{'type': 'archive'}],
        }, validate=True, session_factory=Session)

        resources = p.run()
        self.assertEqual(1, len(resources))

        client = local_session(Session).client(
            'azure.mgmt.machinelearningservices.MachineLearningServicesMgmtClient')
        job = client.jobs.get(
            ResourceIdParser.get_resource_group(resources[0]['id']),
            ResourceIdParser.get_resource_name(resources[0]['c7n:parent-id']),
            resources[0]['name'],
        )
        self.assertTrue(job.properties.is_archived)

    def test_machine_learning_job_raise_on_exception_false(self):
        # Stale Resource Graph entries for deleted workspaces yield 404s on job
        # enumeration. raise_on_exception=False ensures those workspaces are
        # skipped with a warning rather than aborting the entire policy run.
        self.assertFalse(MachineLearningJob.resource_type.raise_on_exception)

    def test_machine_learning_job_continues_after_failed_workspace(self):
        # When one workspace raises ResourceNotFoundError during child enumeration
        # (e.g. a ghost entry in Azure Resource Graph for a deleted workspace),
        # the run should continue and return jobs from healthy workspaces.
        ghost_parent = {
            'id': '/subscriptions/sub/resourceGroups/rg-ghost/providers/'
                  'Microsoft.MachineLearningServices/workspaces/ghost-ws',
            'name': 'ghost-ws',
            'resourceGroup': 'rg-ghost',
        }
        good_parent = {
            'id': '/subscriptions/sub/resourceGroups/rg/providers/'
                  'Microsoft.MachineLearningServices/workspaces/good-ws',
            'name': 'good-ws',
            'resourceGroup': 'rg',
        }
        good_job = {
            'id': '/subscriptions/sub/resourceGroups/rg/providers/'
                  'Microsoft.MachineLearningServices/workspaces/good-ws/jobs/job1',
            'name': 'job1',
            'resourceGroup': 'rg',
            'type': 'Microsoft.MachineLearningServices/workspaces/jobs',
            'properties': {'jobType': 'Command'},
        }

        parent_manager = Mock()
        parent_manager.resource_type.id = 'id'
        parent_manager.resources.return_value = [ghost_parent, good_parent]

        p = self.load_policy({
            'name': 'find-all-machine-learning-jobs',
            'resource': 'azure.machine-learning-job',
        })
        manager = p.resource_manager
        manager.get_parent_manager = Mock(return_value=parent_manager)

        def enumerate_side_effect(parent, type_info, **kwargs):
            if parent['name'] == 'ghost-ws':
                raise ResourceNotFoundError('ParentResourceNotFound')
            return [good_job]

        manager.enumerate_resources = Mock(side_effect=enumerate_side_effect)

        resources = manager.resources()

        self.assertEqual(1, len(resources))
        self.assertEqual('job1', resources[0]['name'])

    @arm_template('machine-learning-job-archive.json')
    @cassette_name('machine-learning-job-archive-skip')
    def test_machine_learning_job_archive_skips_archived_job(self):
        p = self.load_policy({
            'name': 'archive-machine-learning-job',
            'resource': 'azure.machine-learning-job',
            'actions': [{'type': 'archive'}],
        }, validate=True, session_factory=Session)
        client = local_session(Session).client(
            'azure.mgmt.machinelearningservices.MachineLearningServicesMgmtClient')
        job = client.jobs.get(
            'test_machine-learning-job-archive',
            'cctest-mlws-archive',
            'cctest-archive-job',
        )
        resource = _serialize(job)

        self.assertTrue(resource['properties']['isArchived'])
        action = MachineLearningJobArchiveAction({'type': 'archive'}, p.resource_manager)
        action._prepare_processing()

        self.assertEqual('already archived', action._process_resource(resource))
