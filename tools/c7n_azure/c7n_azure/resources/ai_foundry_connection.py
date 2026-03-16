# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import requests

from c7n_azure import constants
from c7n_azure.actions.base import AzureBaseAction
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ChildArmResourceManager
from c7n.utils import type_schema


WRITABLE_PROPERTIES_SCHEMA = {
    'authType': {'type': 'string'},
    'category': {'type': 'string'},
    'target': {'type': 'string'},
    'metadata': {'type': 'object'},
    'isSharedToAll': {'type': 'boolean'},
    'group': {'type': 'string'},
    'expiryTime': {'type': ['string', 'null']},
    'useWorkspaceManagedIdentity': {'type': 'boolean'},
    'sharedUserList': {'type': 'array'},
}


@resources.register('ai-foundry-connection')
class AIFoundryConnection(ChildArmResourceManager):
    """Azure AI Foundry Project Connection Resource."""

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        api_version = '2025-06-01'
        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'
        # Enumeration uses a direct ARM REST call in enumerate_resources.
        enum_spec = ('resources', 'list', None)
        parent_manager_name = 'ai-foundry-project'
        resource_type = 'Microsoft.CognitiveServices/accounts/projects/connections'
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            '"c7n:parent-id"'
        )

    def enumerate_resources(self, parent_resource, type_info, vault_url=None, **params):
        # Generic ARM /resources listing does not reliably return connection children.
        # Query the connections endpoint per project parent.
        session = self.get_session()
        session._initialize_session()
        token = session.credentials.get_token(constants.RESOURCE_GLOBAL_MGMT + '.default')

        url = (
            f"{constants.RESOURCE_GLOBAL_MGMT}{parent_resource['id'].lstrip('/')}"
            f"/connections?api-version={self.resource_type.api_version}"
        )
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get('value', [])


class AIFoundryConnectionUpdateAction(AzureBaseAction):
    """Update an Azure AI Foundry project connection using ARM PATCH."""

    WRITABLE_PROPERTY_KEYS = tuple(WRITABLE_PROPERTIES_SCHEMA.keys())
    schema = type_schema(
        'update',
        required=['properties'],
        properties={
            'type': 'object',
            'additionalProperties': False,
            'properties': WRITABLE_PROPERTIES_SCHEMA
        }
    )
    schema_alias = True

    def _process_resource(self, resource):
        session = self.manager.get_session()
        session._initialize_session()
        token = session.credentials.get_token(constants.RESOURCE_GLOBAL_MGMT + '.default')

        url = (
            f"{constants.RESOURCE_GLOBAL_MGMT}{resource['id'].lstrip('/')}"
            f"?api-version={self.manager.resource_type.api_version}"
        )
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json'
        }

        current_properties = resource.get('properties', {})
        desired_properties = dict(current_properties)
        desired_properties.update(self.data['properties'])

        # Keep the request minimal and include required discriminator fields.
        normalized = {
            key: desired_properties[key]
            for key in self.WRITABLE_PROPERTY_KEYS
            if key in desired_properties
        }

        payload = {'properties': normalized}
        response = requests.patch(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        return "updated"


def register_ai_foundry_connection_actions(registry, resource_class):
    if resource_class is AIFoundryConnection:
        resource_class.action_registry.register('update', AIFoundryConnectionUpdateAction)


resources.subscribe(register_ai_foundry_connection_actions)
