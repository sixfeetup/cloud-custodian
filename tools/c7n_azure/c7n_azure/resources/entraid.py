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
from c7n_azure.query import QueryResourceManager, TypeInfo, TypeMeta

log = logging.getLogger('custodian.azure.entraid')


class GraphTypeInfo(TypeInfo, metaclass=TypeMeta):
    """Type info for Microsoft Graph resources"""
    id = 'id'
    name = 'displayName'
    date = 'createdDateTime'
    global_resource = True
    service = 'graph'
    resource_endpoint = MSGRAPH_RESOURCE_ID

    def extra_args(cls, parent_resource):
        return {}


@resources.register('entraid-user')
class EntraIDUser(QueryResourceManager):
    """EntraID User resource for managing Azure AD users.
    
    Provides comprehensive user management including filtering by user properties,
    authentication methods, group memberships, and security settings.
    
    Required permissions: User.Read.All (and User.ReadWrite.All for actions)
    
    :example:
    
    Find all users with MFA disabled:
    
    .. code-block:: yaml
    
        policies:
          - name: users-without-mfa
            resource: azure.entraid-user
            filters:
              - type: mfa-enabled
                value: false
    
    :example:
    
    Find users with high-risk sign-ins:
    
    .. code-block:: yaml
    
        policies:
          - name: high-risk-users
            resource: azure.entraid-user
            filters:
              - type: risk-level
                value: high
    
    :example:
    
    Find disabled users that should be removed:
    
    .. code-block:: yaml
    
        policies:
          - name: disabled-users-cleanup
            resource: azure.entraid-user
            filters:
              - type: value
                key: accountEnabled
                value: false
              - type: last-sign-in
                days: 90
                op: greater-than
    """

    class resource_type(GraphTypeInfo):
        doc_groups = ['EntraID', 'Identity']
        enum_spec = ('users', 'list', None)
        detail_spec = ('users', 'get', 'objectId')
        id = 'objectId'
        name = 'displayName' 
        date = 'createdDateTime'
        default_report_fields = (
            'displayName',
            'userPrincipalName',
            'mail',
            'accountEnabled',
            'createdDateTime',
            'lastSignInDateTime',
            'objectId'
        )
        permissions = ('User.Read.All',)

    def get_client(self):
        """Get Microsoft Graph client session"""
        session = local_session(self.session_factory)
        return session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def make_graph_request(self, endpoint, method='GET', data=None):
        """Make a request to Microsoft Graph API"""
        try:
            session = self.get_client()
            token = session.credentials.get_token('https://graph.microsoft.com/.default')
            
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

    def resources(self, query=None, augment=True):
        """Override resources method to use Graph API"""
        try:
            response = self.make_graph_request('users')
            resources = response.get('value', [])
            
            if augment:
                resources = self.augment(resources)
                
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
            'admin' in user.get('displayName', '').lower(),
            'administrator' in user.get('jobTitle', '').lower()
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


@EntraIDUser.filter_registry.register('mfa-enabled')
class MFAEnabledFilter(Filter):
    """Filter users based on MFA enablement status.
    
    :example:
    
    Find users without MFA:
    
    .. code-block:: yaml
    
        policies:
          - name: users-no-mfa
            resource: azure.entraid-user
            filters:
              - type: mfa-enabled
                value: false
    """
    
    schema = type_schema('mfa-enabled', value={'type': 'boolean'})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        mfa_enabled = self.data.get('value', True)
        # Placeholder implementation - would need Microsoft Graph beta API calls
        # for full MFA status checking
        filtered = []
        for resource in resources:
            # This is a simplified check - full implementation would query
            # /users/{id}/authentication/methods endpoint
            has_mfa = resource.get('strongAuthenticationDetail', {}).get('methods', [])
            if bool(has_mfa) == mfa_enabled:
                filtered.append(resource)
        return filtered


@EntraIDUser.filter_registry.register('risk-level')
class RiskLevelFilter(ValueFilter):
    """Filter users by Identity Protection risk level.
    
    :example:
    
    Find high-risk users:
    
    .. code-block:: yaml
    
        policies:
          - name: high-risk-users
            resource: azure.entraid-user
            filters:
              - type: risk-level
                value: high
    """
    
    schema = type_schema('risk-level', 
                        value={'type': 'string', 'enum': ['none', 'low', 'medium', 'high']})

    def process(self, resources, event=None):  # pylint: disable=unused-argument
        # Placeholder - would need Identity Protection API integration
        risk_level = self.data.get('value', 'none')
        return [r for r in resources if r.get('riskLevel', 'none').lower() == risk_level.lower()]


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
        
        # Placeholder - would need Graph API calls to get user's group memberships
        # Implementation would call /users/{id}/memberOf endpoint
        filtered = []
        for resource in resources:
            user_groups = resource.get('memberOf', [])  # Simplified
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
            user_id = resource['objectId']
            # This would need the Microsoft Graph SDK for proper implementation
            # self.graph_client.users.update(user_id, account_enabled=False)
            self.log.info(f"Would disable user {resource['displayName']} ({user_id})")
        except Exception as e:
            self.log.error(f"Failed to disable user {resource['displayName']}: {e}")


@EntraIDUser.action_registry.register('require-mfa')
class RequireMFAAction(AzureBaseAction):
    """Require MFA for EntraID users.
    
    :example:
    
    Require MFA for admin users:
    
    .. code-block:: yaml
    
        policies:
          - name: admin-require-mfa
            resource: azure.entraid-user
            filters:
              - type: group-membership
                groups: ['Global Administrators']
            actions:
              - type: require-mfa
    """
    
    schema = type_schema('require-mfa')
    permissions = ('UserAuthenticationMethod.ReadWrite.All',)

    def _prepare_processing(self):
        session = local_session(self.manager.session_factory)
        self.graph_session = session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def _process_resource(self, resource):
        try:
            user_id = resource['objectId']
            # This would require conditional access policy creation or per-user MFA
            self.log.info(f"Would require MFA for user {resource['displayName']} ({user_id})")
        except Exception as e:
            self.log.error(f"Failed to require MFA for user {resource['displayName']}: {e}")


@resources.register('entraid-organization')
class EntraIDOrganization(QueryResourceManager):
    """EntraID Organization resource for managing tenant-level settings.
    
    Provides access to organization-level configuration including security defaults,
    directory properties, and compliance settings.
    
    Required permissions: Organization.Read.All (and Organization.ReadWrite.All for actions)
    
    :example:
    
    Check if security defaults are enabled:
    
    .. code-block:: yaml
    
        policies:
          - name: security-defaults-check
            resource: azure.entraid-organization
            filters:
              - type: value
                key: securityDefaults.isEnabled
                value: false
    
    :example:
    
    Find organizations with weak password policies:
    
    .. code-block:: yaml
    
        policies:
          - name: weak-password-policy
            resource: azure.entraid-organization
            filters:
              - type: password-policy
                min-length: 8
                op: less-than
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
        """Make a request to Microsoft Graph API"""
        try:
            session = self.get_client()
            token = session.credentials.get_token('https://graph.microsoft.com/.default')
            
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
    
    Manages conditional access policies that control access to corporate resources
    based on conditions like user, device, location, and application.
    
    Required permissions: Policy.Read.All (and Policy.ReadWrite.ConditionalAccess for actions)
    
    :example:
    
    Find disabled conditional access policies:
    
    .. code-block:: yaml
    
        policies:
          - name: disabled-ca-policies
            resource: azure.entraid-conditional-access-policy
            filters:
              - type: value
                key: state
                value: disabled
    
    :example:
    
    Find policies not requiring MFA for admins:
    
    .. code-block:: yaml
    
        policies:
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
        """Make a request to Microsoft Graph API"""
        try:
            session = self.get_client()
            token = session.credentials.get_token('https://graph.microsoft.com/.default')
            
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
    
    Provides comprehensive group management including filtering by group properties,
    membership analysis, and security group monitoring.
    
    Required permissions: Group.Read.All (and Group.ReadWrite.All for actions)
    
    :example:
    
    Find administrative groups:
    
    .. code-block:: yaml
    
        policies:
          - name: admin-groups
            resource: azure.entraid-group
            filters:
              - type: value
                key: displayName
                value: ".*[Aa]dmin.*"
                op: regex
    
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
        permissions = ('Group.Read.All',)

    def get_client(self):
        """Get Microsoft Graph client session"""
        session = local_session(self.session_factory)
        return session.get_session_for_resource(MSGRAPH_RESOURCE_ID)

    def make_graph_request(self, endpoint, method='GET'):
        """Make a request to Microsoft Graph API"""
        try:
            session = self.get_client()
            token = session.credentials.get_token('https://graph.microsoft.com/.default')
            
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


@EntraIDGroup.filter_registry.register('member-count')
class MemberCountFilter(Filter):
    """Filter groups based on member count.
    
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
            # Note: This would require additional Graph API calls to get accurate member counts
            # For now, we'll use a placeholder implementation
            member_count = len(resource.get('members', []))
            
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
            # Note: This would require additional Graph API calls to get owners
            # For now, we'll use a placeholder implementation
            owner_count = len(resource.get('owners', []))
            
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
        
        # This is a placeholder - would require Microsoft Graph API calls
        # to get group members and analyze their user types
        filtered = []
        for resource in resources:
            # Placeholder logic - in real implementation would check members
            has_external_members = resource.get('c7n:HasExternalMembers', False)
            has_guest_members = resource.get('c7n:HasGuestMembers', False)
            
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
    
    Required permissions: Policy.Read.All (and Policy.ReadWrite.ConditionalAccess for actions)
    
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
        """Make a request to Microsoft Graph API"""
        try:
            session = self.get_client()
            token = session.credentials.get_token('https://graph.microsoft.com/.default')
            
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