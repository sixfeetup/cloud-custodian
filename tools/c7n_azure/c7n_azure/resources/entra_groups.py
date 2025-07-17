# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.query import QueryResourceManager
from c7n.filters import ValueFilter
from c7n.utils import type_schema


@resources.register('entra-group')
class EntraGroup(QueryResourceManager):
    """Azure Entra ID Group Resource

    :example:

    Find all security groups:

    .. code-block:: yaml

        policies:
          - name: find-security-groups
            resource: azure.entra-group
            filters:
              - type: value
                key: securityEnabled
                value: true

    :example:

    Find groups with many members:

    .. code-block:: yaml

        policies:
          - name: find-large-groups
            resource: azure.entra-group
            filters:
              - type: member-count
                op: greater-than
                value: 100

    :example:

    Find groups with admin roles:

    .. code-block:: yaml

        policies:
          - name: find-admin-groups
            resource: azure.entra-group
            filters:
              - type: directory-role
                key: displayName
                op: contains
                value: Administrator
    """

    class resource_type(QueryResourceManager.resource_type):
        doc_groups = ['Identity']
        
        # Microsoft Graph service configuration
        service = 'msgraph'
        client = 'GraphServiceClient'
        
        # Microsoft Graph specific enumeration
        enum_spec = ('groups', 'list', None)
        
        # Graph uses different field names
        id = 'id'
        name = 'displayName'
        
        default_report_fields = (
            'id',
            'displayName',
            'mail',
            'groupTypes',
            'securityEnabled',
            'createdDateTime'
        )

    @property
    def source_type(self):
        return 'describe-graph'

    def get_client(self):
        """Override to get Microsoft Graph client"""
        return self.get_session().client('msgraph.GraphServiceClient')

    def enumerate_resources(self, **params):
        """Custom enumeration for Microsoft Graph groups"""
        client = self.get_client()
        
        try:
            groups_response = client.groups.get()
            groups = groups_response.value if groups_response and groups_response.value else []
            return [self.serialize_graph_resource(group) for group in groups]
        except Exception as e:
            self.log.error("Failed to enumerate groups from Microsoft Graph: %s", e)
            raise

    def serialize_graph_resource(self, resource):
        """Convert Graph SDK resource to dictionary"""
        return {
            'id': resource.id,
            'displayName': resource.display_name,
            'mail': resource.mail,
            'groupTypes': resource.group_types or [],
            'securityEnabled': resource.security_enabled,
            'mailEnabled': resource.mail_enabled,
            'createdDateTime': resource.created_date_time.isoformat() if resource.created_date_time else None,
            'description': resource.description,
            'visibility': resource.visibility,
            'proxyAddresses': resource.proxy_addresses or [],
            'renewedDateTime': resource.renewed_date_time.isoformat() if resource.renewed_date_time else None,
            'expirationDateTime': resource.expiration_date_time.isoformat() if resource.expiration_date_time else None,
            'membershipRule': resource.membership_rule,
            'membershipRuleProcessingState': resource.membership_rule_processing_state,
            'preferredDataLocation': resource.preferred_data_location,
            'securityIdentifier': resource.security_identifier
        }


@EntraGroup.filter_registry.register('member-count')
class MemberCountFilter(ValueFilter):
    """Filter groups by their member count

    :example:

    Find groups with more than 50 members:

    .. code-block:: yaml

        policies:
          - name: find-large-groups
            resource: azure.entra-group
            filters:
              - type: member-count
                op: greater-than
                value: 50

    :example:

    Find empty groups:

    .. code-block:: yaml

        policies:
          - name: find-empty-groups
            resource: azure.entra-group
            filters:
              - type: member-count
                op: eq
                value: 0
    """
    
    schema = type_schema('member-count', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        client = self.manager.get_client()
        
        for resource in resources:
            try:
                group_id = resource['id']
                # Get group members count
                members_response = client.groups.by_group_id(group_id).members.get()
                members = members_response.value if members_response and members_response.value else []
                
                resource['c7n:member-count'] = len(members)
            except Exception as e:
                self.log.warning("Failed to get member count for group %s: %s", group_id, e)
                resource['c7n:member-count'] = 0
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:member-count', 0))


@EntraGroup.filter_registry.register('directory-role')
class DirectoryRoleFilter(ValueFilter):
    """Filter groups by their directory role assignments

    :example:

    Find groups with Global Administrator role:

    .. code-block:: yaml

        policies:
          - name: find-admin-groups
            resource: azure.entra-group
            filters:
              - type: directory-role
                key: displayName
                op: eq
                value: Global Administrator

    :example:

    Find groups with any admin role:

    .. code-block:: yaml

        policies:
          - name: find-any-admin-groups
            resource: azure.entra-group
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
                group_id = resource['id']
                # Microsoft Graph call for role memberships
                member_of_response = client.groups.by_group_id(group_id).member_of.get()
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
                self.log.warning("Failed to get directory roles for group %s: %s", group_id, e)
                resource['c7n:directory-roles'] = []
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:directory-roles', []))


@EntraGroup.filter_registry.register('owners')
class OwnersFilter(ValueFilter):
    """Filter groups by their owners

    :example:

    Find groups with no owners:

    .. code-block:: yaml

        policies:
          - name: find-orphaned-groups
            resource: azure.entra-group
            filters:
              - type: owners
                key: length([])
                op: eq
                value: 0

    :example:

    Find groups owned by specific user:

    .. code-block:: yaml

        policies:
          - name: find-groups-by-owner
            resource: azure.entra-group
            filters:
              - type: owners
                key: userPrincipalName
                op: contains
                value: admin@example.com
    """
    
    schema = type_schema('owners', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        client = self.manager.get_client()
        
        for resource in resources:
            try:
                group_id = resource['id']
                # Get group owners
                owners_response = client.groups.by_group_id(group_id).owners.get()
                owners = owners_response.value if owners_response and owners_response.value else []
                
                resource['c7n:owners'] = [
                    {
                        'id': owner.id,
                        'displayName': getattr(owner, 'display_name', None),
                        'userPrincipalName': getattr(owner, 'user_principal_name', None),
                        'userType': getattr(owner, 'user_type', None),
                        'objectType': owner.odata_type.split('.')[-1] if hasattr(owner, 'odata_type') else None
                    }
                    for owner in owners
                ]
            except Exception as e:
                self.log.warning("Failed to get owners for group %s: %s", group_id, e)
                resource['c7n:owners'] = []
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:owners', []))


@EntraGroup.filter_registry.register('group-type')
class GroupTypeFilter(ValueFilter):
    """Filter groups by their type (Office 365, Security, etc.)

    :example:

    Find Office 365 groups:

    .. code-block:: yaml

        policies:
          - name: find-office365-groups
            resource: azure.entra-group
            filters:
              - type: group-type
                key: groupTypes
                op: contains
                value: Unified

    :example:

    Find distribution groups:

    .. code-block:: yaml

        policies:
          - name: find-distribution-groups
            resource: azure.entra-group
            filters:
              - type: value
                key: mailEnabled
                value: true
              - type: value
                key: securityEnabled
                value: false
    """
    
    schema = type_schema('group-type', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        # Add group type classification
        for resource in resources:
            group_types = resource.get('groupTypes', [])
            mail_enabled = resource.get('mailEnabled', False)
            security_enabled = resource.get('securityEnabled', False)
            
            if 'Unified' in group_types:
                resource['c7n:group-type'] = 'Office365'
            elif security_enabled and not mail_enabled:
                resource['c7n:group-type'] = 'Security'
            elif mail_enabled and not security_enabled:
                resource['c7n:group-type'] = 'Distribution'
            elif mail_enabled and security_enabled:
                resource['c7n:group-type'] = 'MailEnabledSecurity'
            else:
                resource['c7n:group-type'] = 'Unknown'
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:group-type', 'Unknown'))