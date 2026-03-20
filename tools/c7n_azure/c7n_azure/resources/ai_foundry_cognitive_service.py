# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.resources.arm import ArmResourceManager, ChildArmResourceManager
from c7n_azure.provider import resources
from c7n_azure.actions.base import AzureBaseAction
from c7n.utils import type_schema


@resources.register('cognitiveservice')
class CognitiveService(ArmResourceManager):
    """Cognitive Services Resource

    :example:

    This policy will find all Cognitive Service accounts with 1000 or more
    total errors over the 72 hours

    .. code-block:: yaml

        policies:
          - name: cogserv-many-failures
            resource: azure.cognitiveservice
            filters:
              - type: metric
                metric: TotalErrors
                op: ge
                aggregation: total
                threshold: 1000
                timeframe: 72
    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        service = 'azure.mgmt.cognitiveservices'
        client = 'CognitiveServicesManagementClient'
        enum_spec = ('accounts', 'list', None)
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            'sku.name'
        )
        resource_type = 'Microsoft.CognitiveServices/accounts'


@resources.register('ai-foundry-cognitiveservice-deployment')
class AiFoundryCognitiveServiceDeployment(ChildArmResourceManager):
    """AI Foundry deployment resource using Cognitive Services list API.

    This resource exists for side-by-side comparison with the REST-based
    implementation in ``azure.ai-foundry-deployment``.
    """

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        api_version = '2025-06-01'

        service = 'azure.mgmt.cognitiveservices'
        client = 'CognitiveServicesManagementClient'
        enum_spec = ('deployments', 'list', None)
        parent_manager_name = 'cognitiveservice'
        resource_type = 'Microsoft.CognitiveServices/accounts/deployments'
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            'type'
        )

        @classmethod
        def extra_args(cls, parent_resource):
            return {
                'resource_group_name': parent_resource['resourceGroup'],
                'account_name': parent_resource['name'],
            }


class AiFoundryCognitiveServiceDeploymentDeleteAction(AzureBaseAction):
    """Delete AI Foundry Cognitive Services deployments."""

    schema = type_schema('delete')
    schema_alias = True

    def _prepare_processing(self):
        self.client = self.manager.get_client('azure.mgmt.resource.ResourceManagementClient')

    def _process_resource(self, resource):
        self.client.resources.begin_delete_by_id(
            resource['id'],
            self.manager.resource_type.api_version,
        )
        return "deleted"


def register_ai_foundry_cognitive_service_deployment_actions(registry, resource_class):
    """Register explicit delete action for nested deployment resources.

    The default ARM delete action resolves api-version from resource id via
    ``session.resource_api_version(resource['id'])``.
    """
    if resource_class is AiFoundryCognitiveServiceDeployment:
        resource_class.action_registry.register(
            'delete',
            AiFoundryCognitiveServiceDeploymentDeleteAction,
        )


resources.subscribe(register_ai_foundry_cognitive_service_deployment_actions)
