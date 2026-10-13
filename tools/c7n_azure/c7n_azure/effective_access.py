# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import functools
import logging
import re

log = logging.getLogger('custodian.azure.effective_access')


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
