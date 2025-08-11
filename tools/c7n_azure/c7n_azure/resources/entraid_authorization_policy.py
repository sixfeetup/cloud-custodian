# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from c7n.filters import Filter
from c7n.utils import type_schema
from c7n_azure.provider import resources
from c7n_azure.graph_utils import (
    GraphResourceManager, GraphTypeInfo, GraphSource, EntraIDDiagnosticSettingsFilter
)

log = logging.getLogger('custodian.azure.entraid.authorization_policy')


@resources.register('entraid-authorization-policy')
class EntraIDAuthorizationPolicy(GraphResourceManager):
    """EntraID Authorization Policy resource for tenant-level authorization settings.

    Provides access to organization-level authorization configuration including
    default user role permissions such as the ability to create applications.

    Permissions: Policy.Read.All

    Available filters: value, allowed-to-create-apps

    :example:

    Check if users can register applications (CIS-B-MAF-4.0.0-6.14):

    .. code-block:: yaml

        policies:
          - name: users-can-register-applications-check
            resource: azure.entraid-authorization-policy
            filters:
              - type: allowed-to-create-apps
                value: true

    Check multiple default user role permissions:

    .. code-block:: yaml

        policies:
          - name: default-user-permissions-audit
            resource: azure.entraid-authorization-policy
            filters:
              - type: value
                key: defaultUserRolePermissions.allowedToCreateApps
                value: false
              - type: value
                key: defaultUserRolePermissions.allowedToCreateSecurityGroups
                value: false
    """

    def __init__(self, ctx, data):
        super().__init__(ctx, data)
        # Use our custom GraphSource instead of the default source
        self.source = GraphSource(self)

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity', 'Authorization']
        enum_spec = ('policies/authorizationPolicy', 'get', None)
        id = 'id'
        name = 'displayName'
        date = None  # Authorization policy doesn't have a creation date
        default_report_fields = (
            'id',
            'displayName',
            'description',
            'defaultUserRolePermissions'
        )
        permissions = ('Policy.Read.All',)

    def get_graph_resources(self):
        """Get authorization policy from Microsoft Graph API."""
        try:
            # The authorization policy endpoint returns a single object, not a collection
            response = self.make_graph_request('policies/authorizationPolicy')
            
            # Wrap single policy in a list for consistent processing
            if response:
                resources = [response]
                log.debug("Retrieved authorization policy from Graph API")
                return resources
            else:
                log.warning("No authorization policy data received from Graph API")
                return []
                
        except Exception as e:
            log.error(f"Error retrieving authorization policy: {e}")
            if "Insufficient privileges" in str(e) or "403" in str(e):
                log.error(
                    "Insufficient privileges to read authorization policy. "
                    "Required permissions: Policy.Read.All"
                )
            return []


@EntraIDAuthorizationPolicy.filter_registry.register('allowed-to-create-apps')
class AllowedToCreateAppsFilter(Filter):
    """Filter based on whether users are allowed to create applications.

    This filter checks the defaultUserRolePermissions.allowedToCreateApps setting
    in the authorization policy, which controls whether regular users can register
    applications in the tenant.

    This is particularly useful for CIS compliance checks like:
    CIS-B-MAF-4.0.0-6.14 'Users can register applications' is set to 'No'

    :example:

    Find if users can register applications (should be false for CIS compliance):

    .. code-block:: yaml

        policies:
          - name: cis-users-cannot-register-apps
            resource: azure.entraid-authorization-policy
            filters:
              - type: allowed-to-create-apps
                value: false

    Find if users can register applications (non-compliant):

    .. code-block:: yaml

        policies:
          - name: users-can-register-apps-violation
            resource: azure.entraid-authorization-policy
            filters:
              - type: allowed-to-create-apps
                value: true
    """

    schema = type_schema('allowed-to-create-apps', value={'type': 'boolean'})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        expected_value = self.data.get('value', False)
        filtered = []

        for resource in resources:
            default_user_permissions = resource.get('defaultUserRolePermissions', {})
            allowed_to_create_apps = default_user_permissions.get('allowedToCreateApps', True)
            
            # Convert to boolean to handle various data types
            allowed_to_create_apps = bool(allowed_to_create_apps)
            expected_value = bool(expected_value)
            
            if allowed_to_create_apps == expected_value:
                # Add computed field for easier reporting
                resource['c7n:AllowedToCreateApps'] = allowed_to_create_apps
                filtered.append(resource)

        return filtered


# Register diagnostic settings filter for EntraID authorization policy
EntraIDAuthorizationPolicy.filter_registry.register(
    'diagnostic-settings', EntraIDDiagnosticSettingsFilter
)