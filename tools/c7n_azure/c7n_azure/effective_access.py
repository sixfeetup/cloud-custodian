# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import functools
import logging
import re

log = logging.getLogger('custodian.azure.effective_access')

ALL_PRINCIPALS = '00000000-0000-0000-0000-000000000000'
GROUP_TYPES = ('Group', 'ForeignGroup')
LEAF_MEMBER_TYPES = ('#microsoft.graph.user', '#microsoft.graph.servicePrincipal')


@functools.lru_cache(maxsize=None)
def _compile(pattern):
    return re.compile('.*'.join(re.escape(part) for part in pattern.split('*')), re.IGNORECASE)


def action_matches(pattern, action):
    """True when a role action pattern covers a concrete action.

    Matching is case-insensitive and ``*`` matches any run of characters.
    """
    return _compile(pattern).fullmatch(action) is not None


def permission_grants(permission, data_action):
    """True when one role permission block grants the data action.

    ``notDataActions`` only cancels ``dataActions`` in the same block.
    """
    granted = any(action_matches(p, data_action) for p in permission.get('dataActions') or [])
    if not granted:
        return False
    return not any(
        action_matches(p, data_action) for p in permission.get('notDataActions') or [])


def permissions_grant(permissions, data_action):
    """True when any permission block of a role grants the data action."""
    return any(permission_grants(p, data_action) for p in permissions or [])


def deny_applies(deny, scope, principal_id, data_action):
    """True when a deny assignment removes the data action from the principal.

    A deny with a ``condition`` never applies, because the filter cannot
    evaluate conditions. A deny that names a group does not match the group's
    members.
    """
    props = deny['properties']
    if props.get('condition'):
        return False
    deny_scope = (props.get('scope') or '').lower()
    if props.get('doNotApplyToChildScopes') and deny_scope != scope.lower():
        return False
    if not permissions_grant(props.get('permissions'), data_action):
        return False
    pid = principal_id.lower()
    named = {(p.get('id') or '').lower() for p in props.get('principals') or []}
    if pid not in named and ALL_PRINCIPALS not in named:
        return False
    excluded = {(p.get('id') or '').lower() for p in props.get('excludePrincipals') or []}
    return pid not in excluded


def access_paths(assignments, role_defs, denies, scope, data_action):
    """Build one access path per role assignment that grants the data action.

    ``role_defs`` maps a lowercased role definition ID to a serialized role
    definition. A missing role raises ``KeyError``.
    """
    paths = []
    for assignment in assignments:
        props = assignment['properties']
        role = role_defs[props['roleDefinitionId'].lower()]
        if not permissions_grant(role['properties'].get('permissions'), data_action):
            continue
        if any(deny_applies(d, scope, props['principalId'], data_action) for d in denies):
            continue
        paths.append({
            'assignmentId': assignment['id'],
            'scope': props.get('scope'),
            'roleName': role['properties'].get('roleName'),
            'principalId': props['principalId'],
            'principalType': props.get('principalType'),
            'condition': props.get('condition'),
        })
    return paths


def classify(paths, approved_group_ids, approved_principal_ids):
    """Split paths into approved and unapproved.

    A path is approved when its principal ID is in ``approved_principal_ids``,
    or its principal is a group whose ID is in ``approved_group_ids``.
    """
    groups = {i.lower() for i in approved_group_ids}
    principals = {i.lower() for i in approved_principal_ids}
    approved, unapproved = [], []
    for path in paths:
        pid = path['principalId'].lower()
        if pid in principals or (path['principalType'] in GROUP_TYPES and pid in groups):
            approved.append(path)
        else:
            unapproved.append(path)
    return approved, unapproved


def members_approved(members, approved_principal_ids):
    """True when every user and service principal member is approved.

    Graph directory objects of any other type, including nested groups, are
    ignored. An empty group has no members and counts as approved.
    """
    approved = {i.lower() for i in approved_principal_ids}
    return all(
        m['id'].lower() in approved
        for m in members if m.get('@odata.type') in LEAF_MEMBER_TYPES)
