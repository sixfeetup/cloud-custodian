# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from ..azure_common import BaseTest, arm_template, cassette_name


class AIFoundryAgentTest(BaseTest):

    def test_ai_foundry_agent_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-ai-foundry-agent',
                'resource': 'azure.ai-foundry-agent'
            }, validate=True)
            self.assertTrue(p)

    @arm_template('ai-foundry-application.json')
    @cassette_name('ai-foundry-agents')
    def test_ai_foundry_agent_query(self):
        app_policy = self.load_policy({
            'name': 'test-ai-foundry-application-prereq',
            'resource': 'azure.ai-foundry-application',
        })

        applications = app_policy.run()
        self.assertGreaterEqual(len(applications), 1)

        p = self.load_policy({
            'name': 'test-ai-foundry-agent-query',
            'resource': 'azure.ai-foundry-agent',
        })

        resources = p.run()
        self.assertGreaterEqual(len(resources), 1)
        self.assertTrue(any('/agents/' in r.get('id', '').lower() for r in resources))

    @arm_template('ai-foundry-application.json')
    @cassette_name('ai-foundry-agents-filter')
    def test_ai_foundry_agent_filter_by_name(self):
        app_policy = self.load_policy({
            'name': 'test-ai-foundry-application-prereq-filter',
            'resource': 'azure.ai-foundry-application',
        })

        applications = app_policy.run()
        self.assertGreaterEqual(len(applications), 1)

        p = self.load_policy({
            'name': 'test-ai-foundry-agent-filter-name',
            'resource': 'azure.ai-foundry-agent',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'op': 'glob',
                    'value': 'cctest-aifoundry-agent-*'
                }
            ]
        })

        resources = p.run()
        self.assertGreaterEqual(len(resources), 1)
        self.assertTrue(
            all(r.get('name', '').startswith('cctest-aifoundry-agent-') for r in resources)
        )
