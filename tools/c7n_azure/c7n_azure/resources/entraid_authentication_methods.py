# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from c7n.filters import Filter
from c7n.utils import type_schema
from c7n_azure.provider import resources
from c7n_azure.graph_utils import GraphResourceManager, GraphTypeInfo, GraphSource

log = logging.getLogger('custodian.azure.entraid.authentication_methods_policy')


@resources.register('entraid-authentication-methods-policy')
class EntraIDAuthenticationMethodsPolicy(GraphResourceManager):
    """EntraID Authentication Methods Policy resource.

    Manages the tenant-wide authentication methods policy that controls which authentication
    methods are allowed, registration requirements, and self-service password reset (SSPR) settings.

    **Minimum Required Permissions:**
    - Policy.Read.AuthenticationMethod - Read authentication methods policy
    - Policy.ReadWrite.AuthenticationMethod - Modify authentication methods policy (actions only)

    **Security Note:** This resource requests ONLY EntraID authentication policy permissions.
    No direct access to user data, SharePoint settings, Exchange settings, or Teams settings.

    **Important:** This resource is critical for CIS compliance controls, particularly:
    - CIS 6.5: Ensure that the "Number of methods required to reset" is set to "2"

    :example:

    Check if SSPR requires 2 methods for password reset:

    .. code-block:: yaml

        policies:
          - name: check-sspr-methods-required
            resource: azure.entraid-authentication-methods-policy
            filters:
              - type: sspr-methods-required
                min_methods: 2

    Check policy migration state:

    .. code-block:: yaml

        policies:
          - name: check-policy-migration
            resource: azure.entraid-authentication-methods-policy
            filters:
              - type: value
                key: policyMigrationState
                value: migrationComplete
    """

    def __init__(self, ctx, data):
        super().__init__(ctx, data)
        # Use our custom GraphSource instead of the default source
        self.source = GraphSource(self)

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity', 'Security', 'Authentication']
        enum_spec = ('policies/authenticationMethodsPolicy', 'get', None)
        id = 'id'
        name = 'displayName'
        default_report_fields = (
            'id',
            'displayName',
            'policyMigrationState',
            'policyVersion',
            'lastModifiedDateTime'
        )
        permissions = ('Policy.Read.AuthenticationMethod',)

    def get_graph_resources(self):
        """Get resources from Microsoft Graph API for use with GraphSource."""
        try:
            # Authentication methods policy endpoint
            policy = self.make_graph_request('policies/authenticationMethodsPolicy')

            log.debug("Retrieved authentication methods policy from Graph API")
            return [policy]
        except Exception as e:
            log.warning(f"Could not retrieve Authentication Methods Policy: {e}")
            return []


@EntraIDAuthenticationMethodsPolicy.filter_registry.register('sspr-methods-required')
class SSPRMethodsRequiredFilter(Filter):
    """Filter based on the number of methods required for SSPR (Self-Service Password Reset).

    This filter helps ensure compliance with security standards that require multiple
    authentication methods for password reset operations.

    **Important for CIS Compliance:**
    - CIS Control 6.5 requires checking that "Number of methods required to reset" is set to "2"

    :example:

    Find policies where SSPR requires fewer than 2 methods:

    .. code-block:: yaml

        policies:
          - name: sspr-insufficient-methods
            resource: azure.entraid-authentication-methods-policy
            filters:
              - type: sspr-methods-required
                min_methods: 2
                op: lt

    Find policies that meet the CIS 6.5 requirement:

    .. code-block:: yaml

        policies:
          - name: sspr-cis-compliant
            resource: azure.entraid-authentication-methods-policy
            filters:
              - type: sspr-methods-required
                min_methods: 2
                op: gte
    """

    schema = type_schema(
        'sspr-methods-required',
        min_methods={'type': 'integer', 'minimum': 1, 'maximum': 3},
        op={'type': 'string', 'enum': ['eq', 'ne', 'lt', 'le', 'gt', 'gte'], 'default': 'gte'}
    )

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        min_methods = self.data.get('min_methods', 2)
        op = self.data.get('op', 'gte')
        filtered = []

        for resource in resources:
            try:
                # Look for SSPR configuration within the authentication methods policy
                # The exact structure may vary based on Microsoft Graph API evolution
                sspr_config = None
                
                # Try to find SSPR settings in various possible locations
                if 'authenticationMethodConfigurations' in resource:
                    configurations = resource['authenticationMethodConfigurations']
                    for config in configurations:
                        if config.get('@odata.type') == '#microsoft.graph.passwordAuthenticationMethod':
                            sspr_config = config
                            break
                
                # Also check for system-wide SSPR settings
                if not sspr_config and 'passwordResetPolicy' in resource:
                    sspr_config = resource['passwordResetPolicy']
                
                # Check for legacy SSPR settings during migration
                if not sspr_config and 'legacySspr' in resource:
                    sspr_config = resource['legacySspr']

                if not sspr_config:
                    log.warning(f"SSPR configuration not found in authentication methods policy: {resource.get('id', 'unknown')}")
                    continue

                # Extract the number of methods required for password reset
                methods_required = None
                
                # Try different possible property names based on API evolution
                for prop_name in ['numberOfMethodsRequired', 'methodsRequired', 'requiredMethods', 'minimumMethodsRequired']:
                    if prop_name in sspr_config:
                        try:
                            methods_required = int(sspr_config[prop_name])
                            break
                        except (ValueError, TypeError):
                            continue

                if methods_required is None:
                    log.warning(f"Could not determine SSPR methods required from policy: {resource.get('id', 'unknown')}")
                    continue

                # Apply comparison operator
                matches = False
                if op == 'eq':
                    matches = methods_required == min_methods
                elif op == 'ne':
                    matches = methods_required != min_methods
                elif op == 'lt':
                    matches = methods_required < min_methods
                elif op == 'le':
                    matches = methods_required <= min_methods
                elif op == 'gt':
                    matches = methods_required > min_methods
                elif op == 'gte':
                    matches = methods_required >= min_methods

                if matches:
                    # Add SSPR methods info to resource for reporting
                    resource['sspr_methods_required'] = methods_required
                    filtered.append(resource)

            except Exception as e:
                log.error(f"Error checking SSPR methods required: {e}")
                continue

        return filtered