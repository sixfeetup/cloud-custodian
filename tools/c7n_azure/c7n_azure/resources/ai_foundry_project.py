# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ChildArmResourceManager


@resources.register('ai-foundry-project')
class AIFoundryProject(ChildArmResourceManager):
    """Azure AI Foundry Project Resource."""

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'
        enum_spec = (
            'resources',
            'list_by_resource_group',
            {
                'resource_group_name': lambda parent: parent['resourceGroup'],
                'filter': lambda parent: (
                    "resourceType eq 'Microsoft.CognitiveServices/accounts/projects'"
                )
            }
        )
        parent_manager_name = 'cognitiveservice'
        resource_type = 'Microsoft.CognitiveServices/accounts/projects'
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            '"c7n:parent-id"'
        )

    @staticmethod
    def _is_project_of_parent(resource, parent_id):
        parent_prefix = "{}/projects/".format(parent_id.rstrip('/').lower())
        return resource.get('id', '').lower().startswith(parent_prefix)

    def enumerate_resources(self, parent_resource, type_info, vault_url=None, **params):
        resources = super().enumerate_resources(parent_resource, type_info, vault_url, **params)
        parent_id = parent_resource['id']
        return [r for r in resources if self._is_project_of_parent(r, parent_id)]
