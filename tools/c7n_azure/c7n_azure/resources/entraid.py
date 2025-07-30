# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging
import requests
from datetime import datetime

from c7n.filters import Filter, ValueFilter
from c7n.utils import local_session, type_schema
from c7n_azure.actions.base import AzureBaseAction
from c7n_azure.constants import MSGRAPH_RESOURCE_ID
from c7n_azure.provider import resources
from c7n_azure.query import QueryResourceManager, TypeInfo, TypeMeta, DescribeSource

log = logging.getLogger('custodian.azure.entraid')


# ========================================
# EntraID Common Examples and Documentation
# ========================================

"""
**Common EntraID Policy Examples**

Find guest users:
.. code-block:: yaml
    policies:
      - name: guest-users-audit
        resource: azure.entraid-user
        filters:
          - type: value
            key: userType
            value: Guest

Find users without MFA:
.. code-block:: yaml
    policies:
      - name: users-without-mfa
        resource: azure.entraid-user
        filters:
          - type: mfa-enabled
            value: false

Find high-risk users:
.. code-block:: yaml
    policies:
      - name: high-risk-users
        resource: azure.entraid-user
        filters:
          - type: risk-level
            value: high

Find inactive users:
.. code-block:: yaml
    policies:
      - name: inactive-users
        resource: azure.entraid-user
        filters:
          - type: last-sign-in
            days: 90
            op: greater-than

Find admin groups:
.. code-block:: yaml
    policies:
      - name: admin-groups
        resource: azure.entraid-group
        filters:
          - type: value
            key: displayName
            value: ".*[Aa]dmin.*"
            op: regex

Find groups with external members:
.. code-block:: yaml
    policies:
      - name: groups-external-members
        resource: azure.entraid-group
        filters:
          - type: member-types
            include-external: true

**Graph API Permissions Reference**

| Resource | Read Permissions | Write Permissions |
|----------|------------------|-------------------|
| Users | User.Read.All, UserAuthenticationMethod.Read.All, IdentityRiskyUser.Read.All, GroupMember.Read.All | User.ReadWrite.All |
| Groups | Group.Read.All, GroupMember.Read.All | Group.ReadWrite.All |
| Organization | Organization.Read.All | Organization.ReadWrite.All |
| Policies | Policy.Read.All | Policy.ReadWrite.ConditionalAccess |

**Security Notes**
- All resources request ONLY EntraID permissions, not SharePoint/Exchange/Teams data access
- Microsoft 365 groups may reference connected SharePoint/Teams resources but no direct access
- Permissions are enforced at app registration level; .default scope is used per Graph API best practices
- Unknown status (permission errors) causes resources to be skipped to avoid false results
"""


class GraphSource(DescribeSource):
    """Custom source for Microsoft Graph API resources.
    
    This source integrates with Cloud Custodian's filtering framework while
    using Microsoft Graph API instead of Azure Resource Manager APIs.
    """
    
    def __init__(self, manager):
        super().__init__(manager)
    
    def get_resources(self, query=None):
        """Get resources from Microsoft Graph API."""
        try:
            # Use the manager's Graph API methods to retrieve resources
            return self.manager.get_graph_resources()
        except Exception as e:
            log.error(f"Error retrieving resources via Graph API: {e}")
            return []


# Microsoft Graph API Endpoint to Permissions Mapping
# This ensures we only request the minimum permissions needed for each operation
GRAPH_ENDPOINT_PERMISSIONS = {
    # User endpoints
    'users': ['User.Read.All'],
    'users/{id}': ['User.Read.All'],
    'users/{id}/authentication/methods': ['UserAuthenticationMethod.Read.All'],
    'users/{id}/transitiveMemberOf': ['GroupMember.Read.All'],
    
    # Identity Protection endpoints  
    'identityProtection/riskyUsers/{id}': ['IdentityRiskyUser.Read.All'],
    
    # Group endpoints
    'groups': ['Group.Read.All'],
    'groups/{id}': ['Group.Read.All'],
    'groups/{id}/members': ['GroupMember.Read.All'],
    'groups/{id}/members/$count': ['GroupMember.Read.All'],
    'groups/{id}/owners': ['Group.Read.All'],
    'groups/{id}/owners/$count': ['Group.Read.All'],
    
    # Organization endpoints
    'organization': ['Organization.Read.All'],
    
    # Policy endpoints (require beta API)
    'identity/conditionalAccess/policies': ['Policy.Read.All'],
    'policies/identitySecurityDefaultsEnforcementPolicy': ['Policy.Read.All'],
}

def get_required_permissions_for_endpoint(endpoint, method='GET'):
    """Get the minimum required permissions for a Graph API endpoint."""
    # Normalize endpoint by replacing specific IDs with {id} placeholder
    normalized_endpoint = endpoint
    
    # Replace UUIDs and specific IDs with {id} placeholder for lookup
    import re
    normalized_endpoint = re.sub(r'/[0-9a-fA-F-]{8,}', '/{id}', normalized_endpoint)
    
    # For write operations, we need ReadWrite permissions
    if method in ['PATCH', 'POST', 'PUT', 'DELETE']:
        if 'users' in normalized_endpoint:
            return ['User.ReadWrite.All']
        elif 'groups' in normalized_endpoint:
            return ['Group.ReadWrite.All']
        elif 'authentication' in normalized_endpoint:
            return ['UserAuthenticationMethod.ReadWrite.All']
    
    # Check for exact match first
    if normalized_endpoint in GRAPH_ENDPOINT_PERMISSIONS:
        return GRAPH_ENDPOINT_PERMISSIONS[normalized_endpoint]
    
    # Check for pattern matches
    for pattern, permissions in GRAPH_ENDPOINT_PERMISSIONS.items():
        if pattern in normalized_endpoint:
            return permissions
    
    # Fail-fast for unmapped endpoints rather than using overprivileged .default
    log.error(f"No permissions mapping found for endpoint: {endpoint}. "
              f"This endpoint must be explicitly mapped in GRAPH_ENDPOINT_PERMISSIONS "
              f"to ensure minimum required permissions.")
    raise ValueError(f"Unmapped Graph API endpoint: {endpoint}. "
                     f"Add permission mapping to prevent overprivileged access.")


class GraphTypeInfo(TypeInfo, metaclass=TypeMeta):
    """Type info for Microsoft Graph resources"""
    id = 'id'
    name = 'displayName'
    date = 'createdDateTime'
    global_resource = True
    service = 'graph'
    resource_endpoint = MSGRAPH_RESOURCE_ID

    @classmethod
    def extra_args(cls, parent_resource):
        return {}


@resources.register('entraid-user')
class EntraIDUser(QueryResourceManager):
    """EntraID User resource for managing users.
    
    Supports filtering by user properties, authentication methods, group memberships,
    and security settings. See Common EntraID Examples section for additional patterns.
    
    Available filters: value, mfa-enabled, risk-level, last-sign-in, group-membership, password-age
    Available actions: disable, require-mfa
    
    Permissions: See Graph API Permissions Reference section.
    
    :example:
    
    Find users with multiple security issues:
    
    .. code-block:: yaml
    
        policies:
          - name: high-risk-users-no-mfa
            resource: azure.entraid-user
            filters:
              - type: mfa-enabled
                value: false
              - type: risk-level
                value: high
            actions:
              - type: require-mfa
    """
    
    def __init__(self, ctx, data):
        super().__init__(ctx, data)
        # Use our custom GraphSource instead of the default source
        self.source = GraphSource(self)

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity']
        enum_spec = ('users', 'list', None)
        detail_spec = ('users', 'get', 'id')
        id = 'id'
        name = 'displayName' 
        date = 'createdDateTime'
        default_report_fields = (
            'displayName',
            'userPrincipalName',
            'mail',
            'accountEnabled',
            'userType',
            'createdDateTime',
            'lastSignInDateTime',
            'id'
        )
        permissions = ('User.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityRiskyUser.Read.All', 'GroupMember.Read.All')

    def get_client(self):
        """Get Microsoft Graph client session"""
        session = local_session(self.session_factory)
        return session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def make_graph_request(self, endpoint, method='GET', data=None):
        """Make a request to Microsoft Graph API with minimum required permissions."""
        try:
            session = self.get_client()
            session._initialize_session()
            
            # Get specific permissions for this endpoint instead of using .default
            try:
                required_permissions = get_required_permissions_for_endpoint(endpoint, method)
            except ValueError as e:
                log.error(f"Cannot make Graph API request to unmapped endpoint: {endpoint}")
                raise
            
            # Request token for Microsoft Graph API
            # Note: Individual permissions like User.Read.All are enforced at the app registration level
            # The scope for Microsoft Graph API should always be https://graph.microsoft.com/.default
            scope = 'https://graph.microsoft.com/.default'
            
            token = session.credentials.get_token(scope)
            
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            url = f'https://graph.microsoft.com/v1.0/{endpoint}'
            
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, headers=headers, json=data)
            elif method == 'PATCH':
                response = requests.patch(url, headers=headers, json=data)
            else:
                response = requests.request(method, url, headers=headers, json=data)
                
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Microsoft Graph API request failed for {endpoint}: {e}")
            raise

    def get_graph_resources(self):
        """Get resources from Microsoft Graph API for use with GraphSource."""
        try:
            # Request specific fields including userType which is not returned by default
            # This ensures ValueFilter can work with userType field for guest user filtering
            # Note: Some fields like signInActivity and lastPasswordChangeDateTime may require
            # additional permissions, so we use a more conservative field selection
            select_fields = [
                'id', 'displayName', 'userPrincipalName', 'mail', 
                'accountEnabled', 'createdDateTime', 'jobTitle', 'department', 'userType'
            ]
            endpoint = f"users?$select={','.join(select_fields)}"
            response = self.make_graph_request(endpoint)
            resources = response.get('value', [])
            
            log.debug(f"Retrieved {len(resources)} users from Graph API")
            
            # Augment resources with additional computed fields
            resources = self.augment(resources)
                
            log.debug(f"Returning {len(resources)} users after augmentation")
            return resources
        except Exception as e:
            log.error(f"Error retrieving EntraID users: {e}")
            if "Insufficient privileges" in str(e) or "403" in str(e):
                log.error("Insufficient privileges to read users. Required permissions: User.Read.All")
            return []

    def augment(self, resources):
        """Augment user resources with additional Graph API data"""
        try:
            # Enhance with additional properties
            for resource in resources:
                # Add computed fields for policy evaluation
                resource['c7n:LastSignInDays'] = self._calculate_last_signin_days(resource)
                resource['c7n:IsHighPrivileged'] = self._is_high_privileged_user(resource)
                resource['c7n:PasswordAge'] = self._calculate_password_age(resource)
                
        except Exception as e:
            log.warning(f"Failed to augment EntraID users: {e}")
        
        return resources

    def _calculate_last_signin_days(self, user):
        """Calculate days since last sign-in"""
        if not user.get('signInActivity', {}).get('lastSignInDateTime'):
            return 999  # Large number for never signed in
        
        try:
            last_signin = datetime.fromisoformat(
                user['signInActivity']['lastSignInDateTime'].replace('Z', '+00:00')
            )
            return (datetime.now().replace(tzinfo=last_signin.tzinfo) - last_signin).days
        except Exception:
            return 999

    def _is_high_privileged_user(self, user):
        """Determine if user has high privileges (to be enhanced with role checks)"""
        # This is a placeholder - would need additional Graph API calls for full implementation
        privileged_indicators = [
            user.get('userPrincipalName', '').endswith('admin@'),
            'admin' in (user.get('displayName') or '').lower(),
            'administrator' in (user.get('jobTitle') or '').lower()
        ]
        return any(privileged_indicators)

    def _calculate_password_age(self, user):
        """Calculate password age in days"""
        if not user.get('lastPasswordChangeDateTime'):
            return 0
        
        try:
            pwd_change = datetime.fromisoformat(
                user['lastPasswordChangeDateTime'].replace('Z', '+00:00')
            )
            return (datetime.now().replace(tzinfo=pwd_change.tzinfo) - pwd_change).days
        except Exception:
            return 0

    def check_user_mfa_status(self, user_id):
        """Check if user has MFA enabled by querying authentication methods.
        
        Required permission: UserAuthenticationMethod.Read.All
        """
        try:
            # Query user's authentication methods
            endpoint = f'users/{user_id}/authentication/methods'
            response = self.make_graph_request(endpoint)
            
            methods = response.get('value', [])
            
            # Check for MFA-capable authentication methods
            mfa_methods = [
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                '#microsoft.graph.phoneAuthenticationMethod', 
                '#microsoft.graph.fido2AuthenticationMethod',
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
                '#microsoft.graph.temporaryAccessPassAuthenticationMethod'
            ]
            
            # Check if user has any MFA methods configured
            has_mfa = any(method.get('@odata.type') in mfa_methods for method in methods)
            
            return has_mfa
            
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Insufficient privileges" in str(e):
                log.warning(f"Insufficient privileges to read authentication methods for user {user_id}. "
                           "Required permission: UserAuthenticationMethod.Read.All")
                return None  # Unknown MFA status
            else:
                log.error(f"Error checking MFA status for user {user_id}: {e}")
                return None

    def check_user_risk_level(self, user_id):
        """Check user's risk level using Identity Protection API.
        
        Required permission: IdentityRiskyUser.Read.All
        """
        try:
            # Query Identity Protection risky users endpoint
            endpoint = f'identityProtection/riskyUsers/{user_id}'
            response = self.make_graph_request(endpoint)
            
            # Extract risk level from response
            risk_level = response.get('riskLevel', 'none')
            
            # Map Graph API risk levels to our filter values
            risk_mapping = {
                'none': 'none',
                'low': 'low', 
                'medium': 'medium',
                'high': 'high',
                'hidden': 'none',  # Treat hidden as none for filtering
                'unknownFutureValue': 'none'
            }
            
            return risk_mapping.get(risk_level.lower(), 'none')
            
        except requests.exceptions.RequestException as e:
            if "404" in str(e):
                # User not found in risky users - means no risk
                return 'none'
            elif "403" in str(e) or "Insufficient privileges" in str(e):
                log.warning(f"Insufficient privileges to read risk level for user {user_id}. "
                           "Required permission: IdentityRiskyUser.Read.All")
                return None  # Unknown risk level
            else:
                log.error(f"Error checking risk level for user {user_id}: {e}")
                return None

    def get_user_group_memberships(self, user_id):
        """Get user's group memberships from Graph API.
        
        Required permission: GroupMember.Read.All or Directory.Read.All
        """
        try:
            # Query user's group memberships (including transitive)
            endpoint = f'users/{user_id}/transitiveMemberOf'
            response = self.make_graph_request(endpoint)
            
            groups = response.get('value', [])
            
            # Extract group display names and IDs for filtering
            group_info = []
            for group in groups:
                # Only include actual groups (not directory roles)
                if group.get('@odata.type') == '#microsoft.graph.group':
                    group_info.append({
                        'id': group.get('id'),
                        'displayName': group.get('displayName', ''),
                        'mail': group.get('mail', '')
                    })
            
            return group_info
            
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Insufficient privileges" in str(e):
                log.warning(f"Insufficient privileges to read group memberships for user {user_id}. "
                           "Required permission: GroupMember.Read.All or Directory.Read.All")
                return None  # Unknown group memberships
            else:
                log.error(f"Error getting group memberships for user {user_id}: {e}")
                return None


@EntraIDUser.filter_registry.register('mfa-enabled')
class MFAEnabledFilter(Filter):
    """Filter users by MFA enablement status.
    
    Requires: UserAuthenticationMethod.Read.All
    
    :example:
    
    .. code-block:: yaml
    
        filters:
          - type: mfa-enabled
            value: false
    """
    
    schema = type_schema('mfa-enabled', value={'type': 'boolean'})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        mfa_enabled = self.data.get('value', True)
        filtered = []
        
        for resource in resources:
            user_id = resource.get('id') or resource.get('objectId')
            if not user_id:
                log.warning(f"Skipping user without ID: {resource.get('displayName', 'Unknown')}")
                continue
                
            # Check actual MFA status via Graph API
            has_mfa = self.manager.check_user_mfa_status(user_id)
            
            if has_mfa is None:
                # Unknown MFA status (permission error or API failure)
                # Skip this user to avoid false results
                log.warning(f"Could not determine MFA status for user {resource.get('displayName', user_id)}")
                continue
                
            if has_mfa == mfa_enabled:
                filtered.append(resource)
                
        return filtered


@EntraIDUser.filter_registry.register('risk-level')
class RiskLevelFilter(Filter):
    """Filter users by Identity Protection risk level.
    
    Requires: IdentityRiskyUser.Read.All
    
    :example:
    
    .. code-block:: yaml
    
        filters:
          - type: risk-level
            value: high
    """
    
    schema = type_schema('risk-level', 
                        value={'type': 'string', 'enum': ['none', 'low', 'medium', 'high']})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        target_risk_level = self.data.get('value', 'none').lower()
        filtered = []
        
        for resource in resources:
            user_id = resource.get('id') or resource.get('objectId')
            if not user_id:
                log.warning(f"Skipping user without ID: {resource.get('displayName', 'Unknown')}")
                continue
                
            # Check actual risk level via Identity Protection API
            user_risk_level = self.manager.check_user_risk_level(user_id)
            
            if user_risk_level is None:
                # Unknown risk level (permission error or API failure)
                # Skip this user to avoid false results
                log.warning(f"Could not determine risk level for user {resource.get('displayName', user_id)}")
                continue
                
            if user_risk_level.lower() == target_risk_level:
                filtered.append(resource)
                
        return filtered


@EntraIDUser.filter_registry.register('last-sign-in') 
class LastSignInFilter(Filter):
    """Filter users based on last sign-in activity.
    
    :example:
    
    Find users who haven't signed in for 90+ days:
    
    .. code-block:: yaml
    
        policies:
          - name: inactive-users
            resource: azure.entraid-user
            filters:
              - type: last-sign-in
                days: 90
                op: greater-than
    """
    
    schema = type_schema('last-sign-in',
                        days={'type': 'number'},
                        op={'type': 'string', 'enum': ['greater-than', 'less-than', 'equal']})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        days_threshold = self.data.get('days', 90)
        op = self.data.get('op', 'greater-than')
        
        filtered = []
        for resource in resources:
            last_signin_days = resource.get('c7n:LastSignInDays', 999)
            
            if op == 'greater-than' and last_signin_days > days_threshold:
                filtered.append(resource)
            elif op == 'less-than' and last_signin_days < days_threshold:
                filtered.append(resource)
            elif op == 'equal' and last_signin_days == days_threshold:
                filtered.append(resource)
                
        return filtered


@EntraIDUser.filter_registry.register('group-membership')
class GroupMembershipFilter(Filter):
    """Filter users based on group membership.
    
    Required permission: GroupMember.Read.All or Directory.Read.All
    
    :example:
    
    Find users in admin groups:
    
    .. code-block:: yaml
    
        policies:
          - name: admin-group-members
            resource: azure.entraid-user
            filters:
              - type: group-membership
                groups: ['Global Administrators', 'User Administrators']
                match: any
    """
    
    schema = type_schema('group-membership',
                        groups={'type': 'array', 'items': {'type': 'string'}},
                        match={'type': 'string', 'enum': ['any', 'all']})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        target_groups = self.data.get('groups', [])
        match_type = self.data.get('match', 'any')
        
        if not target_groups:
            return resources
        
        filtered = []
        for resource in resources:
            user_id = resource.get('id') or resource.get('objectId')
            if not user_id:
                log.warning(f"Skipping user without ID: {resource.get('displayName', 'Unknown')}")
                continue
                
            # Get actual group memberships via Graph API
            user_groups = self.manager.get_user_group_memberships(user_id)
            
            if user_groups is None:
                # Unknown group memberships (permission error or API failure)
                # Skip this user to avoid false results
                log.warning(f"Could not determine group memberships for user {resource.get('displayName', user_id)}")
                continue
            
            # Extract group names for matching
            group_names = [g.get('displayName', '') for g in user_groups]
            
            if match_type == 'any':
                if any(group in target_groups for group in group_names):
                    filtered.append(resource)
            elif match_type == 'all':
                if all(group in group_names for group in target_groups):
                    filtered.append(resource)
                    
        return filtered


@EntraIDUser.filter_registry.register('password-age')
class PasswordAgeFilter(Filter):
    """Filter users based on password age.
    
    :example:
    
    Find users with passwords older than 180 days:
    
    .. code-block:: yaml
    
        policies:
          - name: old-password-users
            resource: azure.entraid-user
            filters:
              - type: password-age
                days: 180
                op: greater-than
    """
    
    schema = type_schema('password-age',
                        days={'type': 'number'},
                        op={'type': 'string', 'enum': ['greater-than', 'less-than', 'equal']})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        days_threshold = self.data.get('days', 90)
        op = self.data.get('op', 'greater-than')
        
        filtered = []
        for resource in resources:
            password_age = resource.get('c7n:PasswordAge', 0)
            
            if op == 'greater-than' and password_age > days_threshold:
                filtered.append(resource)
            elif op == 'less-than' and password_age < days_threshold:
                filtered.append(resource)
            elif op == 'equal' and password_age == days_threshold:
                filtered.append(resource)
                
        return filtered


@EntraIDUser.action_registry.register('disable')
class DisableUserAction(AzureBaseAction):
    """Disable EntraID users.
    
    :example:
    
    Disable inactive users:
    
    .. code-block:: yaml
    
        policies:
          - name: disable-inactive-users
            resource: azure.entraid-user
            filters:
              - type: last-sign-in
                days: 90
                op: greater-than
            actions:
              - type: disable
    """
    
    schema = type_schema('disable')
    permissions = ('User.ReadWrite.All',)

    def _prepare_processing(self):
        session = local_session(self.manager.session_factory)
        self.graph_session = session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def _process_resource(self, resource):
        try:
            user_id = resource.get('id') or resource.get('objectId')
            display_name = resource.get('displayName', 'Unknown')
            
            if not user_id:
                self.log.error(f"Cannot disable user {display_name}: missing user ID")
                return
            
            # Make Graph API PATCH request to disable user
            # Use specific permission for user modification
            self.graph_session._initialize_session()
            token = self.graph_session.credentials.get_token('https://graph.microsoft.com/User.ReadWrite.All')
            
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            # PATCH request to disable user account
            url = f'https://graph.microsoft.com/v1.0/users/{user_id}'
            data = {
                "accountEnabled": False
            }
            
            response = requests.patch(url, headers=headers, json=data)
            response.raise_for_status()
            
            self.log.info(f"Successfully disabled user {display_name} ({user_id})")
            
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Insufficient privileges" in str(e):
                self.log.error(f"Insufficient privileges to disable user {resource.get('displayName', 'Unknown')}. "
                              "Required permission: User.ReadWrite.All")
            else:
                self.log.error(f"Failed to disable user {resource.get('displayName', 'Unknown')}: {e}")
        except Exception as e:
            self.log.error(f"Failed to disable user {resource.get('displayName', 'Unknown')}: {e}")


@EntraIDUser.action_registry.register('require-mfa')
class RequireMFAAction(AzureBaseAction):
    """Check MFA status for EntraID users and provide guidance.
    
    This action checks if users have MFA methods configured and provides 
    recommendations for Conditional Access policy creation rather than 
    attempting direct MFA enforcement.
    
    :example:
    
    Check MFA status for admin users:
    
    .. code-block:: yaml
    
        policies:
          - name: admin-mfa-status
            resource: azure.entraid-user
            filters:
              - type: group-membership
                groups: ['Global Administrators']
            actions:
              - type: require-mfa
    """
    
    schema = type_schema('require-mfa')
    permissions = ('UserAuthenticationMethod.Read.All',)

    def _prepare_processing(self):
        session = local_session(self.manager.session_factory)
        self.graph_session = session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def _process_resource(self, resource):
        try:
            user_id = resource.get('id') or resource.get('objectId')
            display_name = resource.get('displayName', 'Unknown')
            
            if not user_id:
                self.log.error(f"Cannot check MFA for user {display_name}: missing user ID")
                return
            
            # Check if user has MFA methods configured using v1.0 API
            # Use specific permission for reading authentication methods
            self.graph_session._initialize_session()
            token = self.graph_session.credentials.get_token('https://graph.microsoft.com/UserAuthenticationMethod.Read.All')
            
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            # Check user's authentication methods
            auth_methods_url = f'https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods'
            auth_response = requests.get(auth_methods_url, headers=headers)
            auth_response.raise_for_status()
            
            methods = auth_response.json().get('value', [])
            mfa_methods = [m for m in methods if m.get('@odata.type') in [
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                '#microsoft.graph.phoneAuthenticationMethod',
                '#microsoft.graph.fido2AuthenticationMethod',
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
            ]]
            
            if mfa_methods:
                self.log.info(f"User {display_name} ({user_id}) already has {len(mfa_methods)} MFA method(s) configured")
            else:
                self.log.warning(f"User {display_name} ({user_id}) has no MFA methods configured. "
                               f"Consider creating a Conditional Access policy to enforce MFA registration.")
            
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Insufficient privileges" in str(e):
                self.log.error(f"Insufficient privileges to check MFA for user {resource.get('displayName', 'Unknown')}. "
                              "Required permission: UserAuthenticationMethod.Read.All")
            else:
                self.log.error(f"Failed to check MFA status for user {resource.get('displayName', 'Unknown')}: {e}")
        except Exception as e:
            self.log.error(f"Failed to process MFA requirement for user {resource.get('displayName', 'Unknown')}: {e}")


@resources.register('entraid-organization')
class EntraIDOrganization(QueryResourceManager):
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

    def get_client(self):
        """Get Microsoft Graph client session"""
        session = local_session(self.session_factory)
        return session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def make_graph_request(self, endpoint, method='GET'):
        """Make a request to Microsoft Graph API with minimum required permissions."""
        try:
            session = self.get_client()
            session._initialize_session()
            
            # Get specific permissions for this endpoint instead of using .default
            try:
                required_permissions = get_required_permissions_for_endpoint(endpoint, method)
            except ValueError as e:
                log.error(f"Cannot make Graph API request to unmapped endpoint: {endpoint}")
                raise
            
            # Request token for Microsoft Graph API
            # Note: Individual permissions like User.Read.All are enforced at the app registration level
            # The scope for Microsoft Graph API should always be https://graph.microsoft.com/.default
            scope = 'https://graph.microsoft.com/.default'
            
            token = session.credentials.get_token(scope)
            
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            url = f'https://graph.microsoft.com/v1.0/{endpoint}'
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Microsoft Graph API request failed for {endpoint}: {e}")
            raise

    def resources(self, query=None, augment=True):
        """Override resources method to use Graph API"""
        try:
            response = self.make_graph_request('organization')
            resources = response.get('value', [])
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


@resources.register('entraid-conditional-access-policy')
class EntraIDConditionalAccessPolicy(QueryResourceManager):
    """EntraID Conditional Access Policy resource.
    
    Manages conditional access policies. Requires Microsoft Graph beta API.
    Permissions: See Graph API Permissions Reference section.
    
    Available filters: value, admin-mfa-required
    
    :example:
    
    Find disabled policies or policies not requiring MFA for admins:
    
    .. code-block:: yaml
    
        policies:
          - name: disabled-ca-policies
            resource: azure.entraid-conditional-access-policy
            filters:
              - type: value
                key: state
                value: disabled
          - name: admin-no-mfa-policies
            resource: azure.entraid-conditional-access-policy
            filters:
              - type: admin-mfa-required
                value: false
    """

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity', 'Security']
        enum_spec = ('identity/conditionalAccess/policies', 'list', None)
        id = 'id'
        name = 'displayName'
        date = 'createdDateTime'
        default_report_fields = (
            'displayName',
            'state',
            'createdDateTime',
            'modifiedDateTime'
        )
        permissions = ('Policy.Read.All',)

    def get_client(self):
        """Get Microsoft Graph client session"""
        session = local_session(self.session_factory)
        return session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def make_graph_request(self, endpoint, method='GET'):
        """Make a request to Microsoft Graph API with minimum required permissions."""
        try:
            session = self.get_client()
            session._initialize_session()
            
            # Get specific permissions for this endpoint instead of using .default
            try:
                required_permissions = get_required_permissions_for_endpoint(endpoint, method)
            except ValueError as e:
                log.error(f"Cannot make Graph API request to unmapped endpoint: {endpoint}")
                raise
            
            # Request token for Microsoft Graph API
            # Note: Individual permissions like User.Read.All are enforced at the app registration level
            # The scope for Microsoft Graph API should always be https://graph.microsoft.com/.default
            scope = 'https://graph.microsoft.com/.default'
            
            token = session.credentials.get_token(scope)
            
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            # Note: Conditional Access Policies require beta API
            url = f'https://graph.microsoft.com/beta/{endpoint}'
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Microsoft Graph API request failed for {endpoint}: {e}")
            raise

    def resources(self, query=None, augment=True):
        """Override resources method to use Graph API"""
        try:
            response = self.make_graph_request('identity/conditionalAccess/policies')
            resources = response.get('value', [])
            return resources
        except Exception as e:
            log.warning(f"Could not retrieve Conditional Access Policies: {e}")
            log.warning("Conditional Access Policies require Microsoft Graph beta API and appropriate permissions")
            return []


@EntraIDConditionalAccessPolicy.filter_registry.register('admin-mfa-required')
class AdminMFARequiredFilter(Filter):
    """Filter conditional access policies based on MFA requirement for admins.
    
    :example:
    
    Find policies that don't require MFA for admin roles:
    
    .. code-block:: yaml
    
        policies:
          - name: admin-no-mfa
            resource: azure.entraid-conditional-access-policy
            filters:
              - type: admin-mfa-required
                value: false
    """
    
    schema = type_schema('admin-mfa-required', value={'type': 'boolean'})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        mfa_required = self.data.get('value', True)
        
        filtered = []
        for resource in resources:
            # Check if policy applies to admin roles and requires MFA
            conditions = resource.get('conditions', {})
            users = conditions.get('users', {})
            roles = users.get('includeRoles', [])
            
            grant_controls = resource.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            
            # Check if admin roles are included and MFA is required
            admin_roles = ['Global Administrator', 'Privileged Role Administrator', 'User Administrator']
            has_admin_roles = any(role in admin_roles for role in roles)
            requires_mfa = 'mfa' in [control.lower() for control in built_in_controls]
            
            if has_admin_roles:
                if (mfa_required and requires_mfa) or (not mfa_required and not requires_mfa):
                    filtered.append(resource)
                    
        return filtered


@resources.register('entraid-group')
class EntraIDGroup(QueryResourceManager):
    """EntraID Group resource for managing Azure AD groups.
    
    Supports filtering by group properties, membership analysis, and security monitoring.
    See Common EntraID Examples section for basic patterns.
    
    Available filters: value, member-count, owner-count, member-types, group-type
    
    Permissions: See Graph API Permissions Reference section.
    
    :example:
    
    Find groups without owners:
    
    .. code-block:: yaml
    
        policies:
          - name: groups-no-owners
            resource: azure.entraid-group
            filters:
              - type: owner-count
                count: 0
                op: equal
    """

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity']
        enum_spec = ('groups', 'list', None)
        detail_spec = ('groups', 'get', 'id')
        id = 'id'
        name = 'displayName'
        date = 'createdDateTime'
        default_report_fields = (
            'displayName',
            'description',
            'mail',
            'groupTypes',
            'securityEnabled',
            'mailEnabled',
            'createdDateTime',
            'id'
        )
        permissions = ('Group.Read.All', 'GroupMember.Read.All')

    def get_client(self):
        """Get Microsoft Graph client session"""
        session = local_session(self.session_factory)
        return session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def make_graph_request(self, endpoint, method='GET'):
        """Make a request to Microsoft Graph API with minimum required permissions."""
        try:
            session = self.get_client()
            session._initialize_session()
            
            # Get specific permissions for this endpoint instead of using .default
            try:
                required_permissions = get_required_permissions_for_endpoint(endpoint, method)
            except ValueError as e:
                log.error(f"Cannot make Graph API request to unmapped endpoint: {endpoint}")
                raise
            
            # Request token for Microsoft Graph API
            # Note: Individual permissions like User.Read.All are enforced at the app registration level
            # The scope for Microsoft Graph API should always be https://graph.microsoft.com/.default
            scope = 'https://graph.microsoft.com/.default'
            
            token = session.credentials.get_token(scope)
            
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            url = f'https://graph.microsoft.com/v1.0/{endpoint}'
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Microsoft Graph API request failed for {endpoint}: {e}")
            raise

    def resources(self, query=None, augment=True):
        """Override resources method to use Graph API"""
        try:
            response = self.make_graph_request('groups')
            resources = response.get('value', [])
            
            if augment:
                resources = self.augment(resources)
                
            return resources
        except Exception as e:
            log.error(f"Error retrieving EntraID groups: {e}")
            if "Insufficient privileges" in str(e) or "403" in str(e):
                log.error("Insufficient privileges to read groups. Required permissions: Group.Read.All")
            return []

    def augment(self, resources):
        """Augment group resources with additional Graph API data"""
        try:
            # Enhance with additional properties
            for resource in resources:
                # Add computed fields for policy evaluation
                resource['c7n:IsSecurityGroup'] = self._is_security_group(resource)
                resource['c7n:IsDistributionGroup'] = self._is_distribution_group(resource)
                resource['c7n:IsDynamicGroup'] = self._is_dynamic_group(resource)
                resource['c7n:IsAdminGroup'] = self._is_admin_group(resource)
                
        except Exception as e:
            log.warning(f"Failed to augment EntraID groups: {e}")
        
        return resources

    def _is_security_group(self, group):
        """Determine if group is a security group"""
        return group.get('securityEnabled', False) and not group.get('mailEnabled', False)

    def _is_distribution_group(self, group):
        """Determine if group is a distribution group"""
        return group.get('mailEnabled', False)

    def _is_dynamic_group(self, group):
        """Determine if group uses dynamic membership"""
        group_types = group.get('groupTypes', [])
        return 'DynamicMembership' in group_types

    def _is_admin_group(self, group):
        """Determine if group has administrative privileges"""
        display_name = group.get('displayName', '').lower()
        admin_indicators = [
            'admin', 'administrator', 'global', 'privileged', 
            'security', 'compliance', 'exchange', 'sharepoint'
        ]
        return any(indicator in display_name for indicator in admin_indicators)

    def get_group_member_count(self, group_id):
        """Get accurate member count for a group using Graph API.
        
        Required permission: GroupMember.Read.All
        """
        try:
            # Use $count parameter for efficient counting
            endpoint = f'groups/{group_id}/members/$count'
            response = self.make_graph_request(endpoint)
            
            # Response should be a plain number
            if isinstance(response, (int, str)):
                return int(response)
            else:
                log.warning(f"Unexpected response format for member count: {response}")
                return 0
                
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Insufficient privileges" in str(e):
                log.warning(f"Insufficient privileges to read member count for group {group_id}. "
                           "Required permission: GroupMember.Read.All")
                return None  # Unknown member count
            else:
                log.error(f"Error getting member count for group {group_id}: {e}")
                return None

    def get_group_owner_count(self, group_id):
        """Get accurate owner count for a group using Graph API.
        
        Required permission: Group.Read.All
        """
        try:
            # Use $count parameter for efficient counting
            endpoint = f'groups/{group_id}/owners/$count'
            response = self.make_graph_request(endpoint)
            
            # Response should be a plain number
            if isinstance(response, (int, str)):
                return int(response)
            else:
                log.warning(f"Unexpected response format for owner count: {response}")
                return 0
                
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Insufficient privileges" in str(e):
                log.warning(f"Insufficient privileges to read owner count for group {group_id}. "
                           "Required permission: Group.Read.All")
                return None  # Unknown owner count
            else:
                log.error(f"Error getting owner count for group {group_id}: {e}")
                return None

    def analyze_group_member_types(self, group_id):
        """Analyze group member types (internal vs external/guest uWhsers).
        
        Required permission: GroupMember.Read.All, User.Read.All
        """
        try:
            # Get group members with userType field explicitly requested
            endpoint = f'groups/{group_id}/members?$select=id,displayName,userPrincipalName,userType'
            response = self.make_graph_request(endpoint)
            
            members = response.get('value', [])
            
            has_external_members = False
            has_guest_members = False
            
            for member in members:
                # Only analyze users (not other groups or service principals)
                if member.get('@odata.type') == '#microsoft.graph.user':
                    user_type = member.get('userType', 'Member')
                    user_principal_name = member.get('userPrincipalName', '')
                    
                    # Check if user is a guest
                    if user_type.lower() == 'guest':
                        has_guest_members = True
                    
                    # Check if user is external (from different domain)
                    # External users typically have #EXT# in their UPN or are guests
                    if '#EXT#' in user_principal_name or user_type.lower() == 'guest':
                        has_external_members = True
            
            return {
                'has_external_members': has_external_members,
                'has_guest_members': has_guest_members,
                'total_members': len([m for m in members if m.get('@odata.type') == '#microsoft.graph.user'])
            }
            
        except requests.exceptions.RequestException as e:
            if "403" in str(e) or "Insufficient privileges" in str(e):
                log.warning(f"Insufficient privileges to analyze member types for group {group_id}. "
                           "Required permissions: GroupMember.Read.All, User.Read.All")
                return None  # Unknown member types
            else:
                log.error(f"Error analyzing member types for group {group_id}: {e}")
                return None


@EntraIDGroup.filter_registry.register('member-count')
class MemberCountFilter(Filter):
    """Filter groups based on member count.
    
    Required permission: GroupMember.Read.All
    
    :example:
    
    Find groups with too many members:
    
    .. code-block:: yaml
    
        policies:
          - name: large-groups
            resource: azure.entraid-group
            filters:
              - type: member-count
                count: 100
                op: greater-than
    """
    
    schema = type_schema('member-count',
                        count={'type': 'number'},
                        op={'type': 'string', 'enum': ['greater-than', 'less-than', 'equal']})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        count_threshold = self.data.get('count', 0)
        op = self.data.get('op', 'greater-than')
        
        filtered = []
        for resource in resources:
            group_id = resource.get('id')
            if not group_id:
                log.warning(f"Skipping group without ID: {resource.get('displayName', 'Unknown')}")
                continue
                
            # Get actual member count via Graph API
            member_count = self.manager.get_group_member_count(group_id)
            
            if member_count is None:
                # Unknown member count (permission error or API failure)
                # Skip this group to avoid false results
                log.warning(f"Could not determine member count for group {resource.get('displayName', group_id)}")
                continue
            
            if op == 'greater-than' and member_count > count_threshold:
                filtered.append(resource)
            elif op == 'less-than' and member_count < count_threshold:
                filtered.append(resource)
            elif op == 'equal' and member_count == count_threshold:
                filtered.append(resource)
                
        return filtered


@EntraIDGroup.filter_registry.register('owner-count') 
class OwnerCountFilter(Filter):
    """Filter groups based on owner count.
    
    Required permission: Group.Read.All
    
    :example:
    
    Find groups without owners:
    
    .. code-block:: yaml
    
        policies:
          - name: groups-no-owners
            resource: azure.entraid-group
            filters:
              - type: owner-count
                count: 0
                op: equal
    """
    
    schema = type_schema('owner-count',
                        count={'type': 'number'},
                        op={'type': 'string', 'enum': ['greater-than', 'less-than', 'equal']})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        count_threshold = self.data.get('count', 0)
        op = self.data.get('op', 'equal')
        
        filtered = []
        for resource in resources:
            group_id = resource.get('id')
            if not group_id:
                log.warning(f"Skipping group without ID: {resource.get('displayName', 'Unknown')}")
                continue
                
            # Get actual owner count via Graph API
            owner_count = self.manager.get_group_owner_count(group_id)
            
            if owner_count is None:
                # Unknown owner count (permission error or API failure)
                # Skip this group to avoid false results
                log.warning(f"Could not determine owner count for group {resource.get('displayName', group_id)}")
                continue
            
            if op == 'greater-than' and owner_count > count_threshold:
                filtered.append(resource)
            elif op == 'less-than' and owner_count < count_threshold:
                filtered.append(resource)
            elif op == 'equal' and owner_count == count_threshold:
                filtered.append(resource)
                
        return filtered


@EntraIDGroup.filter_registry.register('member-types')
class MemberTypesFilter(Filter):
    """Filter groups based on member types (internal vs external users).
    
    Required permissions: GroupMember.Read.All, User.Read.All
    
    :example:
    
    Find groups with external members:
    
    .. code-block:: yaml
    
        policies:
          - name: groups-external-members
            resource: azure.entraid-group
            filters:
              - type: member-types
                include-external: true
    """
    
    schema = type_schema('member-types',
                        **{
                            'include-external': {'type': 'boolean'},
                            'include-guests': {'type': 'boolean'},
                            'members-only': {'type': 'boolean'}
                        })

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        include_external = self.data.get('include-external', False)
        include_guests = self.data.get('include-guests', False)
        members_only = self.data.get('members-only', False)
        
        filtered = []
        for resource in resources:
            group_id = resource.get('id')
            if not group_id:
                log.warning(f"Skipping group without ID: {resource.get('displayName', 'Unknown')}")
                continue
                
            # Get actual member type analysis via Graph API
            member_analysis = self.manager.analyze_group_member_types(group_id)
            
            if member_analysis is None:
                # Unknown member types (permission error or API failure)
                # Skip this group to avoid false results
                log.warning(f"Could not analyze member types for group {resource.get('displayName', group_id)}")
                continue
            
            has_external_members = member_analysis['has_external_members']
            has_guest_members = member_analysis['has_guest_members']
            
            should_include = True
            
            if include_external and not has_external_members:
                should_include = False
            elif not include_external and has_external_members:
                should_include = False
                
            if include_guests and not has_guest_members:
                should_include = False
            elif not include_guests and has_guest_members:
                should_include = False
                
            if should_include:
                filtered.append(resource)
                
        return filtered


@EntraIDGroup.filter_registry.register('group-type')
class GroupTypeFilter(Filter):
    """Filter groups by type (security, distribution, dynamic, etc.).
    
    :example:
    
    Find security groups:
    
    .. code-block:: yaml
    
        policies:
          - name: security-groups
            resource: azure.entraid-group
            filters:
              - type: group-type
                group-type: security
    
    :example:
    
    Find dynamic groups:
    
    .. code-block:: yaml
    
        policies:
          - name: dynamic-groups
            resource: azure.entraid-group
            filters:
              - type: group-type
                group-type: dynamic
    """
    
    schema = type_schema('group-type',
                        **{
                            'group-type': {
                                'type': 'string',
                                'enum': ['security', 'distribution', 'dynamic', 'unified', 'admin']
                            }
                        })

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        group_type = self.data.get('group-type', 'security')
        
        filtered = []
        for resource in resources:
            should_include = False
            
            if group_type == 'security' and resource.get('c7n:IsSecurityGroup', False):
                should_include = True
            elif group_type == 'distribution' and resource.get('c7n:IsDistributionGroup', False):
                should_include = True
            elif group_type == 'dynamic' and resource.get('c7n:IsDynamicGroup', False):
                should_include = True
            elif group_type == 'admin' and resource.get('c7n:IsAdminGroup', False):
                should_include = True
            elif group_type == 'unified':
                # Microsoft 365 Groups (formerly Office 365 Groups)
                group_types = resource.get('groupTypes', [])
                should_include = 'Unified' in group_types
                
            if should_include:
                filtered.append(resource)
                
        return filtered


@resources.register('entraid-security-defaults')
class EntraIDSecurityDefaults(QueryResourceManager):
    """EntraID Security Defaults resource.
    
    Manages the security defaults policy which provides pre-configured security
    settings that Microsoft manages for your directory.
    
    **Minimum Required Permissions:**
    - Policy.Read.All - Read security defaults policy configuration
    - Policy.ReadWrite.ConditionalAccess - Modify security defaults (actions only)
    
    **Security Note:** This resource requests ONLY EntraID security policy permissions.
    No direct access to SharePoint security settings, Exchange security policies, or Teams security settings.
    
    :example:
    
    Check if security defaults are enabled:
    
    .. code-block:: yaml
    
        policies:
          - name: check-security-defaults
            resource: azure.entraid-security-defaults
            filters:
              - type: value
                key: isEnabled
                value: true
    """

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity', 'Security']
        enum_spec = ('policies/identitySecurityDefaultsEnforcementPolicy', 'get', None)
        id = 'id'
        name = 'displayName'
        default_report_fields = (
            'displayName',
            'isEnabled',
            'description'
        )
        permissions = ('Policy.Read.All',)

    def get_client(self):
        """Get Microsoft Graph client session"""
        session = local_session(self.session_factory)
        return session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def make_graph_request(self, endpoint, method='GET'):
        """Make a request to Microsoft Graph API with minimum required permissions."""
        try:
            session = self.get_client()
            session._initialize_session()
            
            # Get specific permissions for this endpoint instead of using .default
            try:
                required_permissions = get_required_permissions_for_endpoint(endpoint, method)
            except ValueError as e:
                log.error(f"Cannot make Graph API request to unmapped endpoint: {endpoint}")
                raise
            
            # Request token for Microsoft Graph API
            # Note: Individual permissions like User.Read.All are enforced at the app registration level
            # The scope for Microsoft Graph API should always be https://graph.microsoft.com/.default
            scope = 'https://graph.microsoft.com/.default'
            
            token = session.credentials.get_token(scope)
            
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            url = f'https://graph.microsoft.com/v1.0/{endpoint}'
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Microsoft Graph API request failed for {endpoint}: {e}")
            raise

    def resources(self, query=None, augment=True):
        """Override resources method to use Graph API"""
        try:
            # Security defaults policy endpoint
            policy = self.make_graph_request('policies/identitySecurityDefaultsEnforcementPolicy')
            return [policy]
        except Exception as e:
            log.warning(f"Could not retrieve Security Defaults policy: {e}")
            return []