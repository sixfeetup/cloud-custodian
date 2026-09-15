# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n.tags import universal_augment
from c7n.filters import MetricsFilter


@resources.register('bedrock-marketplace-model-endpoint')
class BedrockMarketplaceModelEndpoint(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'bedrock'
        enum_spec = ('list_marketplace_model_endpoints', 'marketplaceModelEndpoints[]', None)
        name = id = arn = 'endpointArn'
        arn_type = 'marketplace-model-endpoint'
        permission_prefix = 'bedrock'
        universal_taggable = object()
        permissions_augment = ("bedrock:ListTagsForResource",)

    augment = universal_augment


@BedrockMarketplaceModelEndpoint.filter_registry.register('metrics')
class MarketplaceModelEndpointMetrics(MetricsFilter):
    """Filter marketplace model endpoints by published AWS/Bedrock metrics.

    AWS/Bedrock publishes ``Invocations``, ``InvocationClientErrors``,
    ``InvocationLatency``, and ``EstimatedTPMQuotaUsage`` for a marketplace
    endpoint's ``ModelId`` dimension -- no token-count metrics.
    ``Invocations`` is the closest available proxy for consumption volume.

    :example:

    Match marketplace model endpoints whose daily invocation count exceeds
    1,000:

    .. code-block:: yaml

        policies:
          - name: bedrock-marketplace-endpoint-daily-invocations
            resource: aws.bedrock-marketplace-model-endpoint
            filters:
              - type: metrics
                name: Invocations
                days: 1
                period: 86400
                period-start: start-of-day
                value: 1000
                op: greater-than
    """

    def get_dimensions(self, resource):
        return [{'Name': 'ModelId', 'Value': resource['endpointArn']}]
