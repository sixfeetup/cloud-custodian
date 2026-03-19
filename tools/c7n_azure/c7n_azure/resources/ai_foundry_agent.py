# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import requests

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ChildArmResourceManager

AI_FOUNDRY_DATA_PLANE_SCOPE = 'https://ai.azure.com/.default'


@resources.register('ai-foundry-agent')
class AIFoundryAgent(ChildArmResourceManager):
    """Azure AI Foundry Application Agent Reference Resource."""

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        api_version = '2025-10-01-preview'
        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'
        # Enumeration uses a direct ARM REST call in enumerate_resources.
        enum_spec = ('resources', 'list', None)
        parent_manager_name = 'ai-foundry-application'
        resource_type = 'Microsoft.CognitiveServices/accounts/projects/applications/agents'
        default_report_fields = (
            'name',
            'id',
            '"c7n:parent-id"'
        )

    @staticmethod
    def _is_agent_of_parent(resource, parent_id):
        parent_prefix = "{}/agents/".format(parent_id.rstrip('/').lower())
        return resource.get('id', '').lower().startswith(parent_prefix)

    @staticmethod
    def _extract_account_and_project_from_parent_id(parent_id):
        parts = parent_id.strip('/').split('/')
        # .../accounts/{account}/projects/{project}/applications/{application}
        account_name = parts[7] if len(parts) > 7 else ''
        project_name = parts[9] if len(parts) > 9 else ''
        return account_name, project_name

    @staticmethod
    def _normalize_agent_reference(parent_resource, agent):
        # Data-plane /agents returns canonical top-level id and name.
        agent_name = agent.get('name', '')
        service_agent_id = agent.get('id', '')

        # Normalize to an ARM-like child id for consistent filtering/reporting.
        if agent_name:
            arm_child_id = "{}/agents/{}".format(parent_resource['id'].rstrip('/'), agent_name)
        else:
            arm_child_id = ''

        normalized = {
            'id': arm_child_id,
            'name': agent_name,
            'type': 'Microsoft.CognitiveServices/accounts/projects/applications/agents',
            'resourceGroup': parent_resource.get('resourceGroup'),
            'properties': {
                'agentId': service_agent_id,
                'agentName': agent_name
            },
            'dataPlane': dict(agent)
        }
        return normalized

    def enumerate_resources(self, parent_resource, type_info, vault_url=None, **params):
        app_agents = parent_resource.get('properties', {}).get('agents', [])
        expected_names = {a.get('agentName') for a in app_agents if a.get('agentName')}
        if not expected_names:
            return []

        account_name, project_name = self._extract_account_and_project_from_parent_id(
            parent_resource['id']
        )

        session = self.get_session()
        session._initialize_session()
        token = session.credentials.get_token(AI_FOUNDRY_DATA_PLANE_SCOPE)
        url = (
            f"https://{account_name}.services.ai.azure.com/api/projects/{project_name}"
            "/agents?api-version=v1"
        )
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        values = response.json().get('data', [])
        values = [v for v in values if v.get('name') in expected_names]
        normalized = [self._normalize_agent_reference(parent_resource, v) for v in values]
        return [r for r in normalized if self._is_agent_of_parent(r, parent_resource['id'])]
