# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

# The flight data in workspace-user-query/ is recorded against a real
# Cloud Identity / Workspace tenant. Recording needs a tenant, a service
# account with domain wide delegation, and a Workspace user with the
# Users > Read privilege to impersonate; see
# docs/source/gcp/examples/workspace-user-mfa.rst for how the pieces fit.
#
# tools/c7n_gcp/tests/terraform/workspace_user_query/workspace-setup.md has
# the laboriously worked out one-time setup for the tenant, service account
# and delegation, and the test users to create.
#
# To re-record:
#
#   1. Temporarily change replay_flight_data to record_flight_data in the
#      test, then:
#
#        export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
#        export GOOGLE_WORKSPACE_SUBJECT=<super-admin@your-domain>
#        export GOOGLE_CLOUD_PROJECT=cloud-custodian
#        uv run pytest tools/c7n_gcp/tests/test_workspace.py -k <test> -s -p no:env
#
#      -p no:env matters: pyproject.toml's [tool.pytest_env] loads test.env
#      inside pytest, which would otherwise override the exports above and
#      put the committed fake credentials back.
#
#   2. Scrub the recording before committing. The recorder sanitizes GCP
#      project names only, so real user ids, addresses, names, the domain,
#      the customer id, and recoveryEmail / recoveryPhone all come through
#      and must be replaced by hand. Delete any stray recordings of calls
#      the test doesn't need.
#
#   3. Change the test back to replay_flight_data and confirm it passes with
#      no other edits.

import json
import os
from unittest import mock

from googleapiclient import discovery_cache

from c7n.config import Bag, Config
from c7n_gcp.resources.workspace import WorkspaceUser
from gcp_common import BaseTest


class WorkspaceUserMetaTest(BaseTest):

    def get_manager(self):
        policy = Bag({'name': 'workspace-users',
                      'resource': 'gcp.workspace-user',
                      'provider_name': 'gcp'})
        ctx = self.get_context(config=Config.empty(), policy=policy)
        return WorkspaceUser(ctx, policy)

    def test_resource_query_defaults_to_my_customer(self):
        self.assertEqual(
            self.get_manager().get_resource_query(),
            {'customer': 'my_customer'})

    def test_resource_query_honors_customer_env(self):
        with mock.patch.dict(
                os.environ, {'GOOGLE_WORKSPACE_CUSTOMER': 'C03abc123'}):
            self.assertEqual(
                self.get_manager().get_resource_query(),
                {'customer': 'C03abc123'})

    def test_urn_has_no_project_or_location(self):
        self.assertEqual(
            WorkspaceUser.resource_type.get_urns(
                [{'id': '100000000000000000003',
                  'primaryEmail': 'no2sv@example.com'}], None),
            ['gcp:admin:::workspace-user/100000000000000000003'])

    def test_declared_scopes_accepted_by_api(self):
        """Workspace authorization is OAuth scopes plus Workspace admin
        roles, so it can't be checked against GCP IAM permissions. Validate
        the declared scopes against the API's own discovery document.
        """
        rt = WorkspaceUser.resource_type
        doc = json.loads(discovery_cache.get_static_doc(rt.service, rt.version))
        method = doc['resources'][rt.component]['methods'][rt.enum_spec[0]]
        self.assertTrue(set(rt.scopes).issubset(method['scopes']))


class WorkspaceUserQueryTest(BaseTest):

    def test_query(self):
        factory = self.replay_flight_data('workspace-user-query')
        policy = self.load_policy(
            {'name': 'workspace-users', 'resource': 'gcp.workspace-user'},
            session_factory=factory)
        resources = policy.run()
        self.assertEqual(len(resources), 5)
        # Exactly one super admin, without naming it.
        self.assertEqual(
            len([r for r in resources if r['isAdmin']]), 1)
        self.assertEqual(
            policy.resource_manager.get_urns(resources)[0],
            'gcp:admin:::workspace-user/100000000000000000001')

    def test_users_without_2sv(self):
        """CIS-B-GCPF-4.0.0-1.2"""
        factory = self.replay_flight_data('workspace-user-query')
        policy = self.load_policy(
            {'name': 'workspace-users-without-mfa',
             'resource': 'gcp.workspace-user',
             'filters': [
                 {'type': 'value',
                  'key': 'isEnrolledIn2Sv',
                  'value': False}]},
            session_factory=factory)
        self.assertEqual(
            [r['primaryEmail'] for r in policy.run()],
            ['user-no-2sv@example.com'])

    def test_delegated_admins_are_distinguishable(self):
        """isAdmin covers super admins only, so CIS 1.3 style policies need
        isDelegatedAdmin too. Not a report field, but filterable.
        """
        factory = self.replay_flight_data('workspace-user-query')
        policy = self.load_policy(
            {'name': 'workspace-delegated-admins',
             'resource': 'gcp.workspace-user',
             'filters': [
                 {'type': 'value',
                  'key': 'isDelegatedAdmin',
                  'value': True}]},
            session_factory=factory)
        self.assertEqual(
            [r['primaryEmail'] for r in policy.run()],
            ['delegated-admin@example.com'])


def test_workspace_user_report_fields(test):
    factory = test.replay_flight_data('workspace-user-query')
    policy = test.load_policy(
        {'name': 'workspace-users', 'resource': 'gcp.workspace-user'},
        session_factory=factory)
    resources = policy.run()
    assert len(resources) == 5
    test.check_report_fields(policy, resources)
