# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.filters import FlowLogsFilter
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager


@resources.register('vnet')
class Vnet(ArmResourceManager):
    """Virtual Networks Resource

    :example:

    This set of policies will find all Virtual Networks that do not have DDOS protection enabled.

    .. code-block:: yaml

        policies:
          - name: find-vnets-ddos-protection-disabled
            resource: azure.vnet
            filters:
              - type: value
                key: properties.enableDdosProtection
                op: equal
                value: False

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Networking']

        service = 'azure.mgmt.network'
        client = 'NetworkManagementClient'
        enum_spec = ('virtual_networks', 'list_all', None)
        resource_type = 'Microsoft.Network/virtualNetworks'


@Vnet.filter_registry.register('flow-logs')
class FlowLogs(FlowLogsFilter):
    """Filter a Virtual Network by its associated (virtual network) flow logs.

    :example:

    Find all virtual networks with no flow logs configured, or with a flow-log
    retention less than 90 days. A retention of 0 days means logs are retained
    indefinitely and is treated as compliant (CIS Azure Foundations 8.8).

    .. code-block:: yaml

        policies:
          - name: vnet-flow-log-retention-below-90-days
            resource: azure.vnet
            filters:
              - or:
                - type: flow-logs
                  key: logs
                  value: empty
                - and:
                  - type: flow-logs
                    key: logs[0].retentionPolicy.days
                    op: ne
                    value: 0
                  - type: flow-logs
                    key: logs[0].retentionPolicy.days
                    op: lt
                    value: 90
    """
