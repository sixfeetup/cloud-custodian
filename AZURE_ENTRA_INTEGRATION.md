# Azure Entra ID (Microsoft Graph) Resources for Cloud Custodian

This enhancement adds support for Azure Entra ID objects to Cloud Custodian by integrating with Microsoft Graph API. The implementation follows the same pattern as AWS resources, using the existing `QueryResourceManager` base class but with Microsoft Graph-specific client handling.

## New Resources Added

### 1. `azure.entra-user` - Azure Entra ID Users
Query and filter Azure AD users using Microsoft Graph.

**Example Filters:**
- `directory-role` - Filter by assigned directory roles
- `license-assignment` - Filter by license assignments
- `sign-in-activity` - Filter by sign-in activity

### 2. `azure.entra-group` - Azure Entra ID Groups
Query and filter Azure AD groups using Microsoft Graph.

**Example Filters:**
- `member-count` - Filter by number of members
- `directory-role` - Filter by assigned directory roles
- `owners` - Filter by group owners
- `group-type` - Filter by group type (Office 365, Security, etc.)

### 3. `azure.entra-application` - Azure Entra ID Applications
Query and filter Azure AD applications using Microsoft Graph.

**Example Filters:**
- `credential-expiry` - Filter by credential expiration
- `api-permissions` - Filter by API permissions
- `sign-in-activity` - Filter by application sign-in activity

## Architecture Changes

### Session Enhancement
- Extended `Session.client()` method to handle Microsoft Graph client requests
- Added support for `msgraph.GraphServiceClient` with proper authentication
- Maintains same session factory pattern as existing Azure resources

### Query Enhancement
- Added `describe-graph` source for Microsoft Graph resources
- Resources use `source_type = 'describe-graph'` to use the new source
- Custom `enumerate_resources()` method for Microsoft Graph API calls

### Resource Pattern
- Uses existing `QueryResourceManager` base class (same as AWS pattern)
- No new base classes needed - just different `service` and `client` configuration
- Custom `serialize_graph_resource()` method to convert Graph SDK objects to dictionaries

## Dependencies

Requires Microsoft Graph SDK:
```bash
pip install msgraph-sdk
```

## Authentication

Uses the existing Azure authentication mechanisms. Requires the following Microsoft Graph API permissions:

- `User.Read.All` - Read all users
- `Group.Read.All` - Read all groups  
- `Application.Read.All` - Read all applications
- `Directory.Read.All` - Read directory data
- `RoleManagement.Read.All` - Read role assignments (for directory-role filters)

## Usage Examples

```yaml
# Find disabled users
- name: find-disabled-users
  resource: azure.entra-user
  filters:
    - type: value
      key: accountEnabled
      value: false

# Find users with admin roles
- name: find-admin-users
  resource: azure.entra-user
  filters:
    - type: directory-role
      key: displayName
      op: contains
      value: Administrator

# Find large groups
- name: find-large-groups
  resource: azure.entra-group
  filters:
    - type: member-count
      op: greater-than
      value: 100

# Find applications with expiring secrets
- name: find-expiring-secrets
  resource: azure.entra-application
  filters:
    - type: credential-expiry
      key: passwordCredentials
      op: less-than
      value_type: age
      value: 30
```

## Implementation Benefits

1. **Follows AWS Pattern**: Same proven architecture as AWS provider
2. **Reuses Existing Infrastructure**: No new base classes or complex inheritance
3. **Consistent API**: Same filter/action patterns work across ARM and Graph resources
4. **Maintainable**: Uses established Cloud Custodian patterns
5. **Extensible**: Easy to add new Microsoft Graph resource types using the same template

## Files Modified

- `tools/c7n_azure/c7n_azure/constants.py` - Added Microsoft Graph constants
- `tools/c7n_azure/c7n_azure/session.py` - Extended client method for Graph support
- `tools/c7n_azure/c7n_azure/query.py` - Added describe-graph source
- `tools/c7n_azure/c7n_azure/resources/resource_map.py` - Added new resource mappings

## Files Added

- `tools/c7n_azure/c7n_azure/resources/entra_users.py` - Entra ID Users resource
- `tools/c7n_azure/c7n_azure/resources/entra_groups.py` - Entra ID Groups resource
- `tools/c7n_azure/c7n_azure/resources/entra_applications.py` - Entra ID Applications resource
- `examples/azure-entra-policies.yaml` - Example policies

## Future Enhancements

- Add `azure.entra-service-principal` resource
- Add `azure.entra-directory-role` resource
- Add actions for managing Entra ID objects
- Add more specialized filters for compliance scenarios