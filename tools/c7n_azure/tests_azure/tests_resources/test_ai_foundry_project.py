# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from ..azure_common import BaseTest, arm_template, cassette_name


class AIFoundryProjectTest(BaseTest):

    def test_ai_foundry_project_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-ai-foundry-project',
                'resource': 'azure.ai-foundry-project'
            }, validate=True)
            self.assertTrue(p)

    @arm_template('ai-foundry-project.json')
    @cassette_name('ai-foundry-projects')
    def test_ai_foundry_project_query(self):
        p = self.load_policy({
            'name': 'test-ai-foundry-project-query',
            'resource': 'azure.ai-foundry-project',
        })

        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertTrue(
            resources[0].get('id', '').lower().endswith('/projects/cctest-aifoundry-project')
        )
