# Statement of Work: Azure Subscription Tagging Support

**Project:** Cloud Custodian - Azure Subscription Tagging Support  
**Created:** 2026-03-04  
**Status:** Not Started

---

## Issue Description

Azure subscriptions support tagging via REST API and PowerShell, but Cloud Custodian's `azure.subscription` resource currently does not support tagging actions. This prevents organizations from applying consistent tagging governance at the subscription level.

Azure docs
- Tags REST API: https://learn.microsoft.com/en-us/rest/api/resources/tags/update-at-scope
- Tagging Guide: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources
- Python SDK: https://learn.microsoft.com/en-us/python/api/azure-mgmt-resource/azure.mgmt.resource.resources.v2021_04_01.operations.tagsoperations

Scope
- Add tagging action support to `azure.subscription` resource
  - Implement `tag_operation_enabled()` method
  - Register standard tagging actions (`tag`, `untag`, `auto-tag-user`, `auto-tag-date`, `tag-trim`, `mark-for-op`)
  - Use existing `TagHelper` infrastructure with subscription scope
  - Handle subscription-specific resource ID format (`/subscriptions/{subscription-id}`)

Permissions
- `Microsoft.Resources/tags/write` - Write tags at subscription scope
- `Microsoft.Resources/tags/read` - Read tags at subscription scope

Acceptance criteria
- Policy works:
  - `resource: azure.subscription`
  - `actions: - type: tag` with tag/value or tags dict
  - `actions: - type: untag` to remove tags
  - `actions: - type: auto-tag-user` for creator tracking
  - `actions: - type: auto-tag-date` for timestamp tracking
- Tests validate tag operations work correctly
- Existing `TagHelper` methods work with subscription resources

---

## Executive Summary

This feature enables tagging support for Azure subscriptions in Cloud Custodian, allowing organizations to apply consistent tagging governance at the subscription level for cost allocation, ownership tracking, and compliance.

**Business Justification:** Subscription-level tags are critical for multi-subscription Azure environments. They enable cost allocation across business units, track subscription ownership, enforce compliance policies, and provide metadata for automation workflows. Without this capability, organizations cannot apply Cloud Custodian's powerful tagging automation to their subscription hierarchy, creating a governance gap.

---

## Project Scope

### In Scope
- [ ] Implement `tag_operation_enabled()` method in `Subscription` class
- [ ] Register standard tagging actions for subscription resource
- [ ] Verify `TagHelper` works with subscription scope format
- [ ] Documentation with inline docstrings and YAML examples
- [ ] Automated tests with cassette/replay data
- [ ] Support for all standard tagging actions: `tag`, `untag`, `auto-tag-user`, `auto-tag-date`, `tag-trim`, `mark-for-op`

### Out of Scope
- Management group tagging (different resource type)
- Tenant-level tagging
- Custom tagging logic beyond standard Cloud Custodian patterns
- Azure Portal UI integration (subscriptions don't support tags in Portal)

---

## Technical Design

### Subscription Tagging Implementation

The implementation will leverage existing Cloud Custodian Azure tagging infrastructure:

1. **Add `tag_operation_enabled()` method** to `Subscription` class
2. **Register tagging actions** in the subscription resource file
3. **Use existing `TagHelper`** which already supports scope-based tagging via `begin_update_at_scope()`

```python
# In tools/c7n_azure/c7n_azure/resources/subscription.py

class Subscription(ResourceManager, metaclass=QueryMeta):
    # ... existing code ...
    
    def tag_operation_enabled(self, resource_type):
        # Subscriptions support tagging via REST API
        return True

# Register tagging actions
Subscription.action_registry.register('tag', Tag)
Subscription.action_registry.register('untag', RemoveTag)
Subscription.action_registry.register('auto-tag-user', AutoTagUser)
Subscription.action_registry.register('auto-tag-date', AutoTagDate)
Subscription.action_registry.register('tag-trim', TagTrim)
Subscription.filter_registry.register('marked-for-op', TagActionFilter)
Subscription.action_registry.register('mark-for-op', TagDelayedAction)
```

### API Integration

- **Service**: Azure Resource Manager
- **API Version**: 2021-04-01 or later
- **Components**: Tags API
- **Primary Method(s)**: 
  - `ResourceManagementClient.tags.begin_update_at_scope(scope, parameters)`
  - Scope format: `/subscriptions/{subscription-id}`
- **Permissions Required**:
  - `Microsoft.Resources/tags/write`
  - `Microsoft.Resources/tags/read`

### Example Usage

```yaml
policies:
  - name: azure-tag-subscription-with-owner
    resource: azure.subscription
    description: Tag subscription with owner information
    actions:
      - type: tag
        tag: Owner
        value: platform-team@example.com

  - name: azure-tag-subscription-cost-center
    resource: azure.subscription
    description: Tag subscription with cost center
    actions:
      - type: tag
        tags:
          CostCenter: "12345"
          Environment: Production
          ManagedBy: CloudCustodian

  - name: azure-auto-tag-subscription-creator
    resource: azure.subscription
    description: Auto-tag subscription with creator
    actions:
      - type: auto-tag-user
        tag: CreatedBy

  - name: azure-remove-old-tags
    resource: azure.subscription
    description: Remove deprecated tags
    actions:
      - type: untag
        tags: [OldTag1, DeprecatedTag2]
```

---

## Deliverables

1. **Source Code**
   - `tools/c7n_azure/c7n_azure/resources/subscription.py` - Add `tag_operation_enabled()` method and register tagging actions

2. **Tests**
   - `tools/c7n_azure/tests_azure/tests_resources/test_subscription.py` - Add tests for tag, untag, and auto-tag actions
   - Test cassettes with recorded API responses

3. **Documentation**
   - Inline docstrings with YAML examples for each tagging action
   - Update subscription resource documentation

---

## Dependencies

- **Existing Infrastructure**:
  - `TagHelper` class (`tools/c7n_azure/c7n_azure/tags.py`) - Already supports scope-based tagging
  - Tagging action classes (`tools/c7n_azure/c7n_azure/actions/tagging.py`)
  - `azure-mgmt-resource` Python SDK

- **Reference Implementations**:
  - `ArmResourceManager.tag_operation_enabled()` - Pattern to follow
  - `ArmResourceManager.register_arm_specific()` - Shows how tagging actions are registered
  - Existing subscription tests for test structure

---

## Success Criteria

1. Subscription resource supports all standard tagging actions (`tag`, `untag`, `auto-tag-user`, `auto-tag-date`, `tag-trim`, `mark-for-op`)
2. Tags can be added, updated, and removed from subscriptions via Cloud Custodian policies
3. `TagHelper.update_resource_tags()` works correctly with subscription scope format
4. Tests pass in both functional and replay modes
5. Code follows Cloud Custodian Azure coding standards
6. Peer review approval
7. Documentation includes clear examples for common use cases

---

## References

### Azure Documentation
- **Tags - Update At Scope**: https://learn.microsoft.com/en-us/rest/api/resources/tags/update-at-scope
- **Tags REST API Overview**: https://learn.microsoft.com/en-us/rest/api/resources/tags
- **Azure Tagging Guide**: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources
- **Python SDK - TagsOperations**: https://learn.microsoft.com/en-us/python/api/azure-mgmt-resource/azure.mgmt.resource.resources.v2021_04_01.operations.tagsoperations

### Cloud Custodian Azure Implementation References

- **Tagging Infrastructure:**
  - `tools/c7n_azure/c7n_azure/tags.py::TagHelper` - Core tagging helper class (lines 8-80)
    - `update_resource_tags()` - Uses `begin_update_at_scope()` which supports subscription scope
    - `add_tags()` - Merges new tags with existing tags
    - `remove_tags()` - Removes specified tags
  - `tools/c7n_azure/c7n_azure/actions/tagging.py::Tag` - Tag action implementation (lines 24-75)
  - `tools/c7n_azure/c7n_azure/actions/tagging.py::RemoveTag` - Untag action (lines 77-120)
  - `tools/c7n_azure/c7n_azure/actions/tagging.py::AutoTagUser` - Auto-tag user action (lines 122-200)
  - `tools/c7n_azure/c7n_azure/actions/tagging.py::AutoTagDate` - Auto-tag date action (lines 202-250)
  - `tools/c7n_azure/c7n_azure/actions/tagging.py::TagTrim` - Tag trim action (lines 380-458)
  - `tools/c7n_azure/c7n_azure/actions/tagging.py::TagDelayedAction` - Mark-for-op action (lines 460-520)

- **ARM Resource Pattern (Reference):**
  - `tools/c7n_azure/c7n_azure/resources/arm.py::ArmResourceManager` - Base class for ARM resources (lines 36-94)
    - `tag_operation_enabled()` method (lines 56-57) - Pattern to implement
    - `register_arm_specific()` method (lines 64-93) - Shows how tagging actions are registered
  - `tools/c7n_azure/c7n_azure/resources/arm.py::arm_tags_unsupported` - List of resources that don't support tagging (lines 18-20)

- **Current Subscription Implementation:**
  - `tools/c7n_azure/c7n_azure/resources/subscription.py::Subscription` - Subscription resource class (lines 19-71)
    - Currently only has `add-policy` action registered
    - Inherits from `ResourceManager` (not `ArmResourceManager`)
    - Uses `SubscriptionClient` for API calls

### Key Methods to Understand

- **`TagHelper.update_resource_tags(tag_action, resource, tags)`**:
  - Uses `client.tags.begin_update_at_scope(resource['id'], tags_patch)`
  - The `resource['id']` for subscriptions is `/subscriptions/{subscription-id}`
  - Already supports subscription scope format

- **`tag_operation_enabled(resource_type)`**:
  - Returns `True` if the resource type supports tagging
  - Must be implemented in `Subscription` class
  - For subscriptions, should always return `True`

### Test References

- **Azure Tagging Tests:**
  - `tools/c7n_azure/tests_azure/test_actions_tag.py` - Tag action tests
  - `tools/c7n_azure/tests_azure/test_actions_untag.py` - Untag action tests
  - `tools/c7n_azure/tests_azure/test_actions_autotag-user.py` - Auto-tag user tests
  - `tools/c7n_azure/tests_azure/test_actions_autotag-date.py` - Auto-tag date tests
  - `tools/c7n_azure/tests_azure/test_actions_tag-trim.py` - Tag trim tests
  - `tools/c7n_azure/tests_azure/test_actions_mark-for-op.py` - Mark-for-op tests

- **Subscription Tests:**
  - `tools/c7n_azure/tests_azure/tests_resources/test_subscription.py` - Existing subscription tests (lines 8-80)
    - Shows test structure for subscription resource
    - Uses `sign_out_patch()` context manager

---

## Timeline Estimate

**Total Estimated Duration:** 3-4 hours

### Breakdown:
- **Phase 1 (Implementation):** 1-1.5 hours
  - Add `tag_operation_enabled()` method to `Subscription` class
  - Register all tagging actions (tag, untag, auto-tag-user, auto-tag-date, tag-trim, mark-for-op)
  - Add necessary imports for tagging action classes

- **Phase 2 (Testing):** 1.5-2 hours
  - Create test methods for each tagging action
  - Record cassette fixtures (requires live Azure environment or mock)
  - Verify tag operations work correctly with subscription scope
  - Test edge cases (empty tags, tag updates, tag removal)
  - Run tests in replay mode to ensure they pass

- **Phase 3 (Documentation & Review):** 0.5-1 hour
  - Add comprehensive docstrings with YAML examples
  - Update SOW with completion status
  - Self-review for code quality and consistency
  - Verify all acceptance criteria are met

---

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| `TagHelper` may not work with subscription scope format | High | Low | The `TagHelper.update_resource_tags()` already uses `begin_update_at_scope()` which supports any scope including subscriptions. Verify with initial test. |
| Subscription resource ID format differs from ARM resources | Medium | Low | Subscription IDs are in format `/subscriptions/{id}` which is already supported by the Tags API. No special handling needed. |
| Azure API permissions may differ for subscription-level tagging | Medium | Low | Document required permissions (`Microsoft.Resources/tags/write`) and test with appropriate RBAC roles. |
| Existing tests may not cover subscription-specific scenarios | Low | Medium | Create comprehensive tests covering all tagging actions. Use existing ARM resource tagging tests as reference. |
| Subscription resource doesn't inherit from `ArmResourceManager` | Low | Low | Manually register tagging actions instead of relying on `register_arm_specific()`. This is a straightforward code addition. |

---

## Implementation Notes

### Key Differences from ARM Resources

1. **No Automatic Registration**: Unlike `ArmResourceManager` resources, subscription doesn't use `register_arm_specific()`, so tagging actions must be manually registered.

2. **Resource ID Format**: Subscriptions use `/subscriptions/{subscription-id}` format, which is already compatible with `TagHelper.update_resource_tags()`.

3. **Client Type**: Subscriptions use `SubscriptionClient` for enumeration, but tagging uses `ResourceManagementClient.tags` which works across all scopes.

### Testing Strategy

1. **Unit Tests**: Test each tagging action (tag, untag, auto-tag-user, etc.) with subscription resources
2. **Integration Tests**: Verify `TagHelper` methods work correctly with subscription scope
3. **Cassette Recording**: Record API responses for replay testing
4. **Edge Cases**: Test empty tags, tag updates, tag removal, and error handling

### Validation Checklist

- [ ] `tag_operation_enabled()` returns `True` for subscriptions
- [ ] All 6 tagging actions are registered and functional
- [ ] `TagHelper.update_resource_tags()` works with subscription scope
- [ ] Tests cover all tagging actions
- [ ] Documentation includes YAML examples
- [ ] Code follows Azure Cloud Custodian patterns

---

**Document Version**: 1.0
**Last Updated**: 2026-03-04
**Author**: Six Feet Up Development Team


