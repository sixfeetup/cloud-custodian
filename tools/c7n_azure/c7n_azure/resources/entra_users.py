# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.query import QueryResourceManager
from c7n.filters import ValueFilter
from c7n.utils import type_schema


@resources.register('entra-user')
class EntraUser(QueryResourceManager):
    """Azure Entra ID User Resource

    :example:

    Find all disabled users:

    .. code-block:: yaml

        policies:
          - name: find-disabled-users
            resource: azure.entra-user
            filters:
              - type: value
                key: accountEnabled
                value: false

    :example:

    Find all users with admin roles:

    .. code-block:: yaml

        policies:
          - name: find-admin-users
            resource: azure.entra-user
            filters:
              - type: directory-role
                key: displayName
                op: contains
                value: Administrator

    :example:

    Find external users:

    .. code-block:: yaml

        policies:
          - name: find-external-users
            resource: azure.entra-user
            filters:
              - type: value
                key: userPrincipalName
                op: regex
                value: '#EXT#'
    """

    class resource_type(QueryResourceManager.resource_type):
        doc_groups = ['Identity']
        
        # Microsoft Graph service configuration
        service = 'msgraph'
        client = 'GraphServiceClient'
        
        # Microsoft Graph specific enumeration
        enum_spec = ('users', 'list', None)
        
        # Graph uses different field names
        id = 'id'
        name = 'displayName'
        
        default_report_fields = (
            'id',
            'displayName', 
            'userPrincipalName',
            'mail',
            'accountEnabled',
            'createdDateTime'
        )

    @property
    def source_type(self):
        return 'describe-graph'

    def get_client(self):
        """Override to get Microsoft Graph client"""
        return self.get_session().client('msgraph.GraphServiceClient')

    def enumerate_resources(self, **params):
        """Custom enumeration for Microsoft Graph users"""
        client = self.get_client()
        
        try:
            users_response = client.users.get()
            users = users_response.value if users_response and users_response.value else []
            return [self.serialize_graph_resource(user) for user in users]
        except Exception as e:
            self.log.error("Failed to enumerate users from Microsoft Graph: %s", e)
            raise

    def serialize_graph_resource(self, resource):
        """Convert Graph SDK resource to dictionary"""
        return {
            'id': resource.id,
            'displayName': resource.display_name,
            'userPrincipalName': resource.user_principal_name,
            'mail': resource.mail,
            'accountEnabled': resource.account_enabled,
            'createdDateTime': resource.created_date_time.isoformat() if resource.created_date_time else None,
            'department': resource.department,
            'jobTitle': resource.job_title,
            'companyName': resource.company_name,
            'officeLocation': resource.office_location,
            'businessPhones': resource.business_phones or [],
            'mobilePhone': resource.mobile_phone,
            'preferredLanguage': resource.preferred_language,
            'surname': resource.surname,
            'givenName': resource.given_name,
            'usageLocation': resource.usage_location,
            'userType': resource.user_type
        }


@EntraUser.filter_registry.register('directory-role')
class DirectoryRoleFilter(ValueFilter):
    """Filter users by their directory role assignments

    :example:

    Find users with Global Administrator role:

    .. code-block:: yaml

        policies:
          - name: find-global-admins
            resource: azure.entra-user
            filters:
              - type: directory-role
                key: displayName
                op: eq
                value: Global Administrator

    :example:

    Find users with any admin role:

    .. code-block:: yaml

        policies:
          - name: find-any-admins
            resource: azure.entra-user
            filters:
              - type: directory-role
                key: displayName
                op: contains
                value: Administrator
    """
    
    schema = type_schema('directory-role', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        client = self.manager.get_client()
        
        for resource in resources:
            try:
                user_id = resource['id']
                # Microsoft Graph call for role memberships
                member_of_response = client.users.by_user_id(user_id).member_of.get()
                member_of = member_of_response.value if member_of_response and member_of_response.value else []
                
                resource['c7n:directory-roles'] = [
                    {
                        'id': role.id,
                        'displayName': role.display_name,
                        'roleTemplateId': getattr(role, 'role_template_id', None),
                        'description': getattr(role, 'description', None)
                    }
                    for role in member_of
                    if hasattr(role, 'role_template_id')  # Directory roles only
                ]
            except Exception as e:
                self.log.warning("Failed to get directory roles for user %s: %s", user_id, e)
                resource['c7n:directory-roles'] = []
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:directory-roles', []))


@EntraUser.filter_registry.register('license-assignment')
class LicenseAssignmentFilter(ValueFilter):
    """Filter users by their license assignments

    :example:

    Find users with Office 365 E5 license:

    .. code-block:: yaml

        policies:
          - name: find-e5-users
            resource: azure.entra-user
            filters:
              - type: license-assignment
                key: skuPartNumber
                op: eq
                value: ENTERPRISEPREMIUM
    """
    
    schema = type_schema('license-assignment', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        client = self.manager.get_client()
        
        for resource in resources:
            try:
                user_id = resource['id']
                # Get user with license details
                user_response = client.users.by_user_id(user_id).get(
                    request_configuration={'query_parameters': {'$select': 'assignedLicenses'}}
                )
                
                assigned_licenses = user_response.assigned_licenses if user_response else []
                
                resource['c7n:license-assignments'] = [
                    {
                        'skuId': license.sku_id,
                        'disabledPlans': license.disabled_plans or []
                    }
                    for license in (assigned_licenses or [])
                ]
            except Exception as e:
                self.log.warning("Failed to get license assignments for user %s: %s", user_id, e)
                resource['c7n:license-assignments'] = []
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:license-assignments', []))


@EntraUser.filter_registry.register('sign-in-activity')
class SignInActivityFilter(ValueFilter):
    """Filter users by their sign-in activity

    :example:

    Find users who haven't signed in for 90 days:

    .. code-block:: yaml

        policies:
          - name: find-inactive-users
            resource: azure.entra-user
            filters:
              - type: sign-in-activity
                key: lastSignInDateTime
                op: less-than
                value_type: age
                value: 90
    """
    
    schema = type_schema('sign-in-activity', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        client = self.manager.get_client()
        
        for resource in resources:
            try:
                user_id = resource['id']
                # Get user with sign-in activity
                user_response = client.users.by_user_id(user_id).get(
                    request_configuration={'query_parameters': {'$select': 'signInActivity'}}
                )
                
                sign_in_activity = user_response.sign_in_activity if user_response else None
                
                if sign_in_activity:
                    resource['c7n:sign-in-activity'] = {
                        'lastSignInDateTime': sign_in_activity.last_sign_in_date_time.isoformat() if sign_in_activity.last_sign_in_date_time else None,
                        'lastNonInteractiveSignInDateTime': sign_in_activity.last_non_interactive_sign_in_date_time.isoformat() if sign_in_activity.last_non_interactive_sign_in_date_time else None
                    }
                else:
                    resource['c7n:sign-in-activity'] = {
                        'lastSignInDateTime': None,
                        'lastNonInteractiveSignInDateTime': None
                    }
            except Exception as e:
                self.log.warning("Failed to get sign-in activity for user %s: %s", user_id, e)
                resource['c7n:sign-in-activity'] = {
                    'lastSignInDateTime': None,
                    'lastNonInteractiveSignInDateTime': None
                }
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:sign-in-activity', {}))