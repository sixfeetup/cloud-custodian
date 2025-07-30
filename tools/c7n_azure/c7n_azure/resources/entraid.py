# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

"""
EntraID (Azure Active Directory) Resources

This module provides access to EntraID resources through the Microsoft Graph API.
Individual resource classes have been split into separate files for better maintainability.

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

# Import all EntraID resources to ensure they are properly registered
from c7n_azure.resources.entraid_user import EntraIDUser  # noqa: F401
from c7n_azure.resources.entraid_group import EntraIDGroup  # noqa: F401
from c7n_azure.resources.entraid_organization import EntraIDOrganization  # noqa: F401
from c7n_azure.resources.entraid_conditional_access import EntraIDConditionalAccessPolicy  # noqa: F401
from c7n_azure.resources.entraid_security_defaults import EntraIDSecurityDefaults  # noqa: F401