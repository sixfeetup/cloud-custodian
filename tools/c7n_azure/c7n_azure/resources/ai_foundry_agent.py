# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ChildArmResourceManager


@resources.register('ai-foundry-agent')
class AIFoundryAgent(ChildArmResourceManager):
    """Azure AI Foundry Application Agent Reference Resource."""

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        api_version = '2025-10-01-preview'
        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'
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
    def _normalize_agent_reference(parent_resource, agent):
        agent_name = agent.get('agentName')
        service_agent_id = agent.get('agentId')
        arm_child_id = "{}/agents/{}".format(parent_resource['id'].rstrip('/'), agent_name)

        normalized = {
            'id': arm_child_id,
            'name': agent_name,
            'type': 'Microsoft.CognitiveServices/accounts/projects/applications/agents',
            'resourceGroup': parent_resource.get('resourceGroup'),
            'properties': {
                'agentId': service_agent_id,
                'agentName': agent_name
            },
            'applicationAgentRef': dict(agent)
        }
        return normalized

    def enumerate_resources(self, parent_resource, type_info, vault_url=None, **params):
        app_agents = parent_resource.get('properties', {}).get('agents', [])
        if not app_agents:
            return []

        normalized = [self._normalize_agent_reference(parent_resource, v) for v in app_agents]
        return [r for r in normalized if self._is_agent_of_parent(r, parent_resource['id'])]
