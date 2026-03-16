# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n.exceptions import PolicyValidationError

from c7n_azure.resources.ai_foundry_connection import AIFoundryConnection

from ..azure_common import BaseTest, arm_template, cassette_name


class AIFoundryConnectionTest(BaseTest):

    def test_ai_foundry_connection_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-ai-foundry-connection',
                'resource': 'azure.ai-foundry-connection'
            }, validate=True)
            self.assertTrue(p)

    def test_ai_foundry_connection_tag_not_supported(self):
        with self.sign_out_patch():
            policy = {
                'name': 'test-ai-foundry-connection-tag',
                'resource': 'azure.ai-foundry-connection',
                'actions': [{'type': 'tag', 'tags': {'env': 'test'}}]
            }
            self.assertRaises(
                PolicyValidationError, self.load_policy, policy, validate=True
            )

    @arm_template('ai-foundry-connection.json')
    @cassette_name('ai-foundry-connections')
    def test_ai_foundry_connection_query(self):
        project_policy = self.load_policy({
            'name': 'test-ai-foundry-project-prereq',
            'resource': 'azure.ai-foundry-project',
        })

        projects = project_policy.run()
        self.assertGreaterEqual(len(projects), 1)

        p = self.load_policy({
            'name': 'test-ai-foundry-connection-query',
            'resource': 'azure.ai-foundry-connection',
        })

        resources = p.run()
        self.assertGreaterEqual(len(resources), 1)
        self.assertIn('/connections/', resources[0].get('id', '').lower())
