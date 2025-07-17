# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.query import QueryResourceManager
from c7n.filters import ValueFilter
from c7n.utils import type_schema


@resources.register('entra-application')
class EntraApplication(QueryResourceManager):
    """Azure Entra ID Application Resource

    :example:

    Find applications with secrets expiring soon:

    .. code-block:: yaml

        policies:
          - name: find-expiring-app-secrets
            resource: azure.entra-application
            filters:
              - type: credential-expiry
                key: passwordCredentials
                op: less-than
                value_type: age
                value: 30

    :example:

    Find applications with overly broad permissions:

    .. code-block:: yaml

        policies:
          - name: find-overprivileged-apps
            resource: azure.entra-application
            filters:
              - type: api-permissions
                key: permission
                op: contains
                value: Directory.ReadWrite.All

    :example:

    Find applications that haven't been used recently:

    .. code-block:: yaml

        policies:
          - name: find-unused-apps
            resource: azure.entra-application
            filters:
              - type: sign-in-activity
                key: lastSignInDateTime
                op: less-than
                value_type: age
                value: 90
    """

    class resource_type(QueryResourceManager.resource_type):
        doc_groups = ['Identity']
        
        # Microsoft Graph service configuration
        service = 'msgraph'
        client = 'GraphServiceClient'
        
        # Microsoft Graph specific enumeration
        enum_spec = ('applications', 'list', None)
        
        # Graph uses different field names
        id = 'id'
        name = 'displayName'
        
        default_report_fields = (
            'id',
            'displayName',
            'appId',
            'createdDateTime',
            'publisherDomain',
            'signInAudience'
        )

    @property
    def source_type(self):
        return 'describe-graph'

    def get_client(self):
        """Override to get Microsoft Graph client"""
        return self.get_session().client('msgraph.GraphServiceClient')

    def enumerate_resources(self, **params):
        """Custom enumeration for Microsoft Graph applications"""
        client = self.get_client()
        
        try:
            applications_response = client.applications.get()
            applications = applications_response.value if applications_response and applications_response.value else []
            return [self.serialize_graph_resource(app) for app in applications]
        except Exception as e:
            self.log.error("Failed to enumerate applications from Microsoft Graph: %s", e)
            raise

    def serialize_graph_resource(self, resource):
        """Convert Graph SDK resource to dictionary"""
        return {
            'id': resource.id,
            'displayName': resource.display_name,
            'appId': resource.app_id,
            'createdDateTime': resource.created_date_time.isoformat() if resource.created_date_time else None,
            'publisherDomain': resource.publisher_domain,
            'signInAudience': resource.sign_in_audience,
            'description': resource.description,
            'homepage': resource.web.home_page_url if resource.web else None,
            'replyUrls': resource.web.redirect_uris if resource.web else [],
            'logoutUrl': resource.web.logout_url if resource.web else None,
            'identifierUris': resource.identifier_uris or [],
            'tags': resource.tags or [],
            'passwordCredentials': [
                {
                    'keyId': cred.key_id,
                    'displayName': cred.display_name,
                    'startDateTime': cred.start_date_time.isoformat() if cred.start_date_time else None,
                    'endDateTime': cred.end_date_time.isoformat() if cred.end_date_time else None,
                    'hint': cred.hint
                }
                for cred in (resource.password_credentials or [])
            ],
            'keyCredentials': [
                {
                    'keyId': cred.key_id,
                    'displayName': cred.display_name,
                    'startDateTime': cred.start_date_time.isoformat() if cred.start_date_time else None,
                    'endDateTime': cred.end_date_time.isoformat() if cred.end_date_time else None,
                    'type': cred.type,
                    'usage': cred.usage
                }
                for cred in (resource.key_credentials or [])
            ],
            'requiredResourceAccess': [
                {
                    'resourceAppId': access.resource_app_id,
                    'resourceAccess': [
                        {
                            'id': perm.id,
                            'type': perm.type
                        }
                        for perm in (access.resource_access or [])
                    ]
                }
                for access in (resource.required_resource_access or [])
            ],
            'isFallbackPublicClient': resource.is_fallback_public_client,
            'groupMembershipClaims': resource.group_membership_claims,
            'oauth2AllowImplicitFlow': resource.web.implicit_grant_settings.enable_access_token_issuance if resource.web and resource.web.implicit_grant_settings else False,
            'oauth2AllowIdTokenImplicitFlow': resource.web.implicit_grant_settings.enable_id_token_issuance if resource.web and resource.web.implicit_grant_settings else False
        }


@EntraApplication.filter_registry.register('credential-expiry')
class CredentialExpiryFilter(ValueFilter):
    """Filter applications by credential expiration

    :example:

    Find applications with secrets expiring in 30 days:

    .. code-block:: yaml

        policies:
          - name: find-expiring-secrets
            resource: azure.entra-application
            filters:
              - type: credential-expiry
                key: passwordCredentials
                op: less-than
                value_type: age
                value: 30

    :example:

    Find applications with expired certificates:

    .. code-block:: yaml

        policies:
          - name: find-expired-certificates
            resource: azure.entra-application
            filters:
              - type: credential-expiry
                key: keyCredentials
                op: less-than
                value_type: age
                value: 0
    """
    
    schema = type_schema('credential-expiry', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        from datetime import datetime, timezone
        
        for resource in resources:
            # Process password credentials
            password_creds = resource.get('passwordCredentials', [])
            for cred in password_creds:
                if cred.get('endDateTime'):
                    try:
                        expiry_date = datetime.fromisoformat(cred['endDateTime'].replace('Z', '+00:00'))
                        days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                        cred['c7n:days-until-expiry'] = days_until_expiry
                        cred['c7n:is-expired'] = days_until_expiry < 0
                    except Exception as e:
                        self.log.warning("Failed to parse expiry date for credential %s: %s", cred.get('keyId'), e)
                        cred['c7n:days-until-expiry'] = None
                        cred['c7n:is-expired'] = False
            
            # Process key credentials
            key_creds = resource.get('keyCredentials', [])
            for cred in key_creds:
                if cred.get('endDateTime'):
                    try:
                        expiry_date = datetime.fromisoformat(cred['endDateTime'].replace('Z', '+00:00'))
                        days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                        cred['c7n:days-until-expiry'] = days_until_expiry
                        cred['c7n:is-expired'] = days_until_expiry < 0
                    except Exception as e:
                        self.log.warning("Failed to parse expiry date for credential %s: %s", cred.get('keyId'), e)
                        cred['c7n:days-until-expiry'] = None
                        cred['c7n:is-expired'] = False
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        # Check the specified credential type
        credential_type = self.data.get('key', 'passwordCredentials')
        credentials = resource.get(credential_type, [])
        
        # Apply filter to each credential
        for cred in credentials:
            if super().__call__(cred):
                return True
        return False


@EntraApplication.filter_registry.register('api-permissions')
class ApiPermissionsFilter(ValueFilter):
    """Filter applications by their API permissions

    :example:

    Find applications with Directory.ReadWrite.All permission:

    .. code-block:: yaml

        policies:
          - name: find-apps-with-directory-write
            resource: azure.entra-application
            filters:
              - type: api-permissions
                key: permission
                op: contains
                value: Directory.ReadWrite.All

    :example:

    Find applications with Microsoft Graph permissions:

    .. code-block:: yaml

        policies:
          - name: find-apps-with-graph-permissions
            resource: azure.entra-application
            filters:
              - type: api-permissions
                key: resourceAppId
                op: eq
                value: 00000003-0000-0000-c000-000000000000
    """
    
    schema = type_schema('api-permissions', rinherit=ValueFilter.schema)
    
    def process(self, resources, event=None):
        # Known API GUIDs for common Microsoft services
        known_apis = {
            '00000003-0000-0000-c000-000000000000': 'Microsoft Graph',
            '00000002-0000-0000-c000-000000000000': 'Azure Active Directory Graph',
            '797f4846-ba00-4fd7-ba43-dac1f8f63013': 'Windows Azure Service Management API',
            '00000001-0000-0000-c000-000000000000': 'Microsoft Graph (Legacy)',
        }
        
        for resource in resources:
            required_access = resource.get('requiredResourceAccess', [])
            
            # Flatten permissions for easier filtering
            permissions = []
            for access in required_access:
                resource_app_id = access.get('resourceAppId')
                resource_name = known_apis.get(resource_app_id, resource_app_id)
                
                for perm in access.get('resourceAccess', []):
                    permissions.append({
                        'resourceAppId': resource_app_id,
                        'resourceName': resource_name,
                        'permissionId': perm.get('id'),
                        'permissionType': perm.get('type'),
                        'permission': f"{resource_name}:{perm.get('id')}"  # Combined for easy filtering
                    })
            
            resource['c7n:api-permissions'] = permissions
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        permissions = resource.get('c7n:api-permissions', [])
        
        # Apply filter to each permission
        for perm in permissions:
            if super().__call__(perm):
                return True
        return False


@EntraApplication.filter_registry.register('sign-in-activity')
class SignInActivityFilter(ValueFilter):
    """Filter applications by their sign-in activity

    :example:

    Find applications with no recent sign-ins:

    .. code-block:: yaml

        policies:
          - name: find-unused-apps
            resource: azure.entra-application
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
                app_id = resource['appId']
                
                # Get service principal for the application
                service_principals_response = client.service_principals.get(
                    request_configuration={
                        'query_parameters': {
                            '$filter': f"appId eq '{app_id}'",
                            '$select': 'id,signInActivity'
                        }
                    }
                )
                
                service_principals = service_principals_response.value if service_principals_response and service_principals_response.value else []
                
                if service_principals:
                    sp = service_principals[0]
                    sign_in_activity = sp.sign_in_activity if hasattr(sp, 'sign_in_activity') else None
                    
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
                else:
                    resource['c7n:sign-in-activity'] = {
                        'lastSignInDateTime': None,
                        'lastNonInteractiveSignInDateTime': None
                    }
            except Exception as e:
                self.log.warning("Failed to get sign-in activity for application %s: %s", app_id, e)
                resource['c7n:sign-in-activity'] = {
                    'lastSignInDateTime': None,
                    'lastNonInteractiveSignInDateTime': None
                }
        
        return super().process(resources, event)
    
    def __call__(self, resource):
        return super().__call__(resource.get('c7n:sign-in-activity', {}))