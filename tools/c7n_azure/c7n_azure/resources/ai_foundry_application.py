# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import requests

from c7n_azure import constants
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ChildArmResourceManager


@resources.register('ai-foundry-application')
class AIFoundryApplication(ChildArmResourceManager):
    """Azure AI Foundry Application Resource."""

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        api_version = '2025-10-01-preview'
        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'
        # Enumeration uses a direct ARM REST call in enumerate_resources.
        enum_spec = ('resources', 'list', None)
        parent_manager_name = 'ai-foundry-project'
        resource_type = 'Microsoft.CognitiveServices/accounts/projects/applications'
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            '"c7n:parent-id"'
        )

    def enumerate_resources(self, parent_resource, type_info, vault_url=None, **params):
        session = self.get_session()
        session._initialize_session()
        token = session.credentials.get_token(constants.RESOURCE_GLOBAL_MGMT + '.default')

        url = (
            f"{constants.RESOURCE_GLOBAL_MGMT}{parent_resource['id'].lstrip('/')}"
            f"/applications?api-version={self.resource_type.api_version}"
        )
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get('value', [])
