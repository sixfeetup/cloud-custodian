# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from c7n.filters import Filter
from c7n.utils import type_schema
from c7n_azure.provider import resources
from c7n_azure.graph_utils import (
    GraphResourceManager, GraphTypeInfo, GraphSource, EntraIDDiagnosticSettingsFilter
)

log = logging.getLogger('custodian.azure.entraid.organization')


@resources.register('entraid-organization')
class EntraIDOrganization(GraphResourceManager):
    """EntraID Organization resource for tenant-level settings.

    Provides access to organization-level configuration.
    Permissions: See Graph API Permissions Reference section.

    Available filters: value, security-defaults

    :example:

    Check if security defaults are disabled:

    .. code-block:: yaml

        policies:
          - name: security-defaults-check
            resource: azure.entraid-organization
            filters:
              - type: security-defaults
                enabled: false
    """

    def __init__(self, ctx, data):
        super().__init__(ctx, data)
        # Use our custom GraphSource instead of the default source
        self.source = GraphSource(self)

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity']
        enum_spec = ('organization', 'list', None)
        id = 'id'
        name = 'displayName'
        date = 'createdDateTime'
        default_report_fields = (
            'displayName',
            'id',
            'createdDateTime',
            'verifiedDomains'
        )
        permissions = ('Organization.Read.All',)

    def get_graph_resources(self):
        """Get resources from Microsoft Graph API for use with GraphSource."""
        try:
            response = self.make_graph_request('organization')
            resources = response.get('value', [])

            log.debug(f"Retrieved {len(resources)} organization settings from Graph API")
            return resources
        except Exception as e:
            log.error(f"Error retrieving organization settings: {e}")
            return []


@EntraIDOrganization.filter_registry.register('security-defaults')
class SecurityDefaultsFilter(Filter):
    """Filter based on security defaults configuration.

    :example:

    Find organizations with security defaults disabled:

    .. code-block:: yaml

        policies:
          - name: security-defaults-disabled
            resource: azure.entraid-organization
            filters:
              - type: security-defaults
                enabled: false
    """

    schema = type_schema('security-defaults', enabled={'type': 'boolean'})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        enabled_required = self.data.get('enabled', True)
        filtered = []
        for resource in resources:
            security_defaults = resource.get('securityDefaults', {})
            is_enabled = security_defaults.get('isEnabled', False)
            if is_enabled == enabled_required:
                filtered.append(resource)
        return filtered


# Register diagnostic settings filter for EntraID organization
EntraIDOrganization.filter_registry.register('diagnostic-settings', EntraIDDiagnosticSettingsFilter)
