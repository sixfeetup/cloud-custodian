# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.resources.ai_foundry_cognitive_service import (
    AiFoundryCognitiveServiceDeployment,
    AiFoundryCognitiveServiceDeploymentDeleteAction,
)


# Reuse the Cognitive Services deployment implementation for AI Foundry.
# The behavioral delta is API version only, so this subclass isolates that
# version override without changing the base deployment resource behavior.
@resources.register('ai-foundry-deployment')
class AiFoundryDeployment(AiFoundryCognitiveServiceDeployment):
    """Azure AI Foundry Deployment Resource.

    Shares implementation with ``azure.cognitiveservice-deployment`` but uses
    the AI Foundry API version.
    """

    class resource_type(AiFoundryCognitiveServiceDeployment.resource_type):
        api_version = '2025-06-01'


def register_ai_foundry_deployment_actions(registry, resource_class):
    """Register explicit delete action for nested deployment resources.

    The default ARM delete action resolves api-version from resource id via
    ``session.resource_api_version(resource['id'])``.
    """
    if resource_class is AiFoundryDeployment:
        resource_class.action_registry.register('delete', AiFoundryCognitiveServiceDeploymentDeleteAction)


resources.subscribe(register_ai_foundry_deployment_actions)
