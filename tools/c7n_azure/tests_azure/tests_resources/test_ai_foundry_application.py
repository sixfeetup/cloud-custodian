# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from ..azure_common import BaseTest, arm_template, cassette_name


class AIFoundryApplicationTest(BaseTest):
    def test_ai_foundry_application_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-ai-foundry-application',
                'resource': 'azure.ai-foundry-application'
            }, validate=True)
            self.assertTrue(p)

    @arm_template('ai-foundry-application.json')
    @cassette_name('ai-foundry-applications')
    def test_ai_foundry_application_query(self):
        project_policy = self.load_policy({
            'name': 'test-ai-foundry-project-prereq',
            'resource': 'azure.ai-foundry-project',
        })

        projects = project_policy.run()
        self.assertGreaterEqual(len(projects), 1)

        p = self.load_policy({
            'name': 'test-ai-foundry-application-query',
            'resource': 'azure.ai-foundry-application',
        })

        resources = p.run()
        self.assertGreaterEqual(len(resources), 1)
        self.assertTrue(
            any(r.get('id', '').lower().endswith('/applications/cctest-aifoundry-application')
                for r in resources)
        )

    @arm_template('ai-foundry-application.json')
    @cassette_name('ai-foundry-applications-filter')
    def test_ai_foundry_application_filter_by_name(self):
        project_policy = self.load_policy({
            'name': 'test-ai-foundry-project-prereq-filter',
            'resource': 'azure.ai-foundry-project',
        })

        projects = project_policy.run()
        self.assertGreaterEqual(len(projects), 1)

        p = self.load_policy({
            'name': 'test-ai-foundry-application-filter-name',
            'resource': 'azure.ai-foundry-application',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'op': 'eq',
                    'value': 'cctest-aifoundry-application'
                }
            ]
        })

        resources = p.run()
        self.assertGreaterEqual(len(resources), 1)
        self.assertTrue(all(r.get('name') == 'cctest-aifoundry-application' for r in resources))
