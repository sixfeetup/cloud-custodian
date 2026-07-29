# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
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
