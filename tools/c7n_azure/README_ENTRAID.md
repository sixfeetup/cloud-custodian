# Azure EntraID Resources for Cloud Custodian

This document describes the Azure EntraID (Azure Active Directory) resource implementations for Cloud Custodian, enabling comprehensive identity and access management policy enforcement.

## Overview

The EntraID resource implementations provide Cloud Custodian with the ability to:

- Manage and monitor Azure AD users
- Enforce conditional access policies
- Audit organizational security settings
- Implement CIS Microsoft Azure Foundations Benchmark controls
- Monitor identity security posture

## Supported Resources

### 1. EntraID Users (`azure.entraid-user`)

Manages Azure AD user accounts with comprehensive filtering and actions.

**Required Permissions:**
- `User.Read.All` (for reading user data)  
- `User.ReadWrite.All` (for user actions)
- `UserAuthenticationMethod.ReadWrite.All` (for MFA actions)

**Key Filters:**
- `mfa-enabled`: Filter users by MFA status
- `last-sign-in`: Filter by last sign-in activity  
- `group-membership`: Filter by group memberships
- `password-age`: Filter by password age
- `risk-level`: Filter by Identity Protection risk level

**Actions:**
- `disable`: Disable user accounts
- `require-mfa`: Enforce MFA requirements

### 2. EntraID Groups (`azure.entraid-group`)

Manages Azure AD groups including security groups, distribution groups, and Microsoft 365 groups.

**Required Permissions:**
- `Group.Read.All` (for reading group data)
- `Group.ReadWrite.All` (for group actions)

**Key Filters:**
- `group-type`: Filter by group type (security, distribution, dynamic, unified, admin)
- `member-count`: Filter by number of group members
- `owner-count`: Filter by number of group owners
- `member-types`: Filter by member types (external, guest users)

**Actions:**
- `delete`: Remove groups (planned)
- `modify-membership`: Add/remove members (planned)

### 3. EntraID Organization (`azure.entraid-organization`)

Manages tenant-level directory settings and policies.

**Required Permissions:**
- `Organization.Read.All` (for reading organization data)
- `Organization.ReadWrite.All` (for organization actions)

**Key Filters:**
- `security-defaults`: Filter by security defaults configuration

### 3. EntraID Conditional Access Policies (`azure.entraid-conditional-access-policy`)

Manages conditional access policies for advanced access controls.

**Required Permissions:**
- `Policy.Read.All` (for reading policies)
- `Policy.ReadWrite.ConditionalAccess` (for policy actions)

**Key Filters:**
- `admin-mfa-required`: Check if policies require MFA for admins

### 4. EntraID Security Defaults (`azure.entraid-security-defaults`)

Manages the security defaults policy configuration.

**Required Permissions:**
- `Policy.Read.All` (for reading security defaults)
- `Policy.ReadWrite.ConditionalAccess` (for security defaults actions)

## CIS Azure Foundations Benchmark Coverage

The EntraID resources enable implementation of these CIS controls:

### Identity and Access Management (CIS Section 1)

| Control | Resource | Filter/Action |
|---------|----------|---------------|
| 1.1 - MFA for privileged users | `entraid-user` | `mfa-enabled` + `group-membership` |
| 1.2 - No guest users | `entraid-user` | `userType` filter |  
| 1.3 - Guest user review | `entraid-user` | `userType` + `last-sign-in` |
| 1.22 - Security defaults enabled | `entraid-organization` | `security-defaults` |
| 1.23 - Password policy | `entraid-organization` | Password policy filters |

### Additional Security Controls

- **User Account Monitoring**: Track inactive accounts, password age, sign-in patterns
- **Privileged Access Management**: Monitor admin accounts, enforce MFA
- **Conditional Access Compliance**: Ensure policies are enabled and properly configured
- **Identity Risk Management**: Monitor high-risk users and sign-ins

## Authentication and Setup

### Service Principal Setup

1. Create an Azure AD application registration
2. Grant required Microsoft Graph permissions
3. Configure authentication (client secret or certificate)

### Required Microsoft Graph Permissions

For full functionality, the service principal needs:

```
User.Read.All
User.ReadWrite.All  
Group.Read.All
Group.ReadWrite.All
Organization.Read.All
Organization.ReadWrite.All
Policy.Read.All
Policy.ReadWrite.ConditionalAccess
UserAuthenticationMethod.ReadWrite.All
```

### Environment Variables

```bash
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"
```

## Example Usage

### Find Users Without MFA

```yaml
policies:
  - name: users-without-mfa
    resource: azure.entraid-user
    filters:
      - type: mfa-enabled
        value: false
    actions:
      - type: require-mfa
```

### Monitor Inactive Admin Accounts

```yaml
policies:
  - name: inactive-admin-accounts
    resource: azure.entraid-user
    filters:
      - type: group-membership
        groups: ['Global Administrators']
        match: any
      - type: last-sign-in
        days: 30
        op: greater-than
```

### Monitor Administrative Groups

```yaml
policies:
  - name: admin-groups-without-owners
    resource: azure.entraid-group
    filters:
      - type: group-type
        group-type: admin
      - type: owner-count
        count: 0
        op: equal
```

### Check Security Defaults

```yaml
policies:
  - name: security-defaults-check
    resource: azure.entraid-organization
    filters:
      - type: security-defaults
        enabled: false
```

### Audit Conditional Access Policies

```yaml
policies:
  - name: disabled-ca-policies
    resource: azure.entraid-conditional-access-policy
    filters:
      - type: value
        key: state
        value: disabled
```

## Implementation Details

### Microsoft Graph API Integration

The implementation uses Microsoft Graph API v1.0 for stable operations and beta endpoints where necessary for advanced features like:

- Conditional access policies
- Security defaults settings  
- User authentication methods
- Identity Protection data

### Caching and Performance

- Resource augmentation adds computed fields like `c7n:LastSignInDays`
- Graph API calls are batched where possible
- Proper error handling for insufficient permissions

### Security Considerations

- All Microsoft Graph permissions follow principle of least privilege
- Sensitive operations (like user disable) require explicit write permissions
- Actions log operations for audit trails

## Limitations and Future Enhancements

### Current Limitations

1. **Beta API Dependencies**: Some features require Microsoft Graph beta endpoints
2. **Permission Requirements**: Requires high-privilege Microsoft Graph permissions
3. **Rate Limiting**: Subject to Microsoft Graph API throttling limits

### Planned Enhancements

1. **Service Principals**: Full support for application/service principal management
2. **Groups**: EntraID group resource implementation  
3. **Roles**: Directory role assignments and PIM integration
4. **Advanced Filters**: More sophisticated filtering options
5. **Microsoft Graph SDK**: Migration to official Microsoft Graph SDK

## Testing

Run EntraID resource tests:

```bash
# Run all EntraID tests
python -m pytest tests_azure/tests_resources/test_entraid.py

# Run specific test
python -m pytest tests_azure/tests_resources/test_entraid.py::EntraIDUserTest::test_mfa_enabled_filter
```

## Contributing

When contributing to EntraID resources:

1. Follow existing Azure resource patterns
2. Include comprehensive tests
3. Document required permissions
4. Add example policies
5. Test with various tenant configurations

## Support

For issues and questions:

1. Check Cloud Custodian documentation
2. Review Microsoft Graph API documentation  
3. File issues in the Cloud Custodian repository
4. Include tenant configuration details (without secrets)

## References

- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Azure AD Conditional Access](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [Cloud Custodian Azure Documentation](https://cloudcustodian.io/docs/azure/)