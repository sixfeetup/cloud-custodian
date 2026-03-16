# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n.exceptions import PolicyValidationError

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

    def test_ai_foundry_connection_update_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-ai-foundry-connection-update',
                'resource': 'azure.ai-foundry-connection',
                'actions': [{
                    'type': 'update',
                    'properties': {
                        'isSharedToAll': True
                    }
                }]
            }, validate=True)
            self.assertTrue(p)

    def test_ai_foundry_connection_update_invalid_field(self):
        with self.sign_out_patch():
            policy = {
                'name': 'test-ai-foundry-connection-update-invalid-field',
                'resource': 'azure.ai-foundry-connection',
                'actions': [{
                    'type': 'update',
                    'properties': {
                        'notWritableField': 'x'
                    }
                }]
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

    @arm_template('ai-foundry-connection.json')
    @cassette_name('ai-foundry-connections-update')
    def test_ai_foundry_connection_update(self):
        read_policy = self.load_policy({
            'name': 'test-ai-foundry-connection-read-before-update',
            'resource': 'azure.ai-foundry-connection',
        })

        before = read_policy.run()
        self.assertEqual(len(before), 1)
        current = before[0].get('properties', {}).get('isSharedToAll', False)
        updated = not current

        update_policy = self.load_policy({
            'name': 'test-ai-foundry-connection-update',
            'resource': 'azure.ai-foundry-connection',
            'actions': [{
                'type': 'update',
                'properties': {
                    'isSharedToAll': updated
                }
            }]
        })

        update_policy.run()
        self.sleep_in_live_mode(10)

        after = read_policy.run()
        self.assertEqual(len(after), 1)
        self.assertEqual(after[0].get('properties', {}).get('isSharedToAll'), updated)
