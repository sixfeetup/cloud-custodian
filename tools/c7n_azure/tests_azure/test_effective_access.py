# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import unittest

from c7n_azure.effective_access import (
    action_matches,
    permission_grants,
    permissions_grant,
)

SCOPE = ('/subscriptions/s1/resourceGroups/rg/providers/'
         'Microsoft.CognitiveServices/accounts/acct')
ACTION = ('Microsoft.CognitiveServices/accounts/OpenAI/deployments/'
          'chat/completions/action')


class ActionMatchingTest(unittest.TestCase):

    def test_exact(self):
        self.assertTrue(action_matches(ACTION, ACTION))

    def test_case_insensitive(self):
        self.assertTrue(action_matches(ACTION.upper(), ACTION.lower()))

    def test_wildcard_run(self):
        self.assertTrue(action_matches('Microsoft.CognitiveServices/*', ACTION))
        self.assertTrue(action_matches('Microsoft.CognitiveServices/accounts/*/action', ACTION))
        self.assertTrue(action_matches('*', ACTION))

    def test_no_partial_match(self):
        self.assertFalse(action_matches('Microsoft.CognitiveServices/accounts', ACTION))
        self.assertFalse(action_matches(ACTION + '/extra', ACTION))
        self.assertFalse(action_matches('Microsoft.Storage/*', ACTION))

    def test_regex_metacharacters_are_literal(self):
        self.assertFalse(action_matches('Microsoft.Cognitive(Services)/*', ACTION))


class PermissionGrantsTest(unittest.TestCase):

    def test_data_action_grants(self):
        self.assertTrue(permission_grants({'dataActions': [ACTION]}, ACTION))

    def test_not_data_action_in_same_block_cancels(self):
        block = {'dataActions': ['Microsoft.CognitiveServices/*'], 'notDataActions': [ACTION]}
        self.assertFalse(permission_grants(block, ACTION))

    def test_not_data_action_for_other_action_keeps_grant(self):
        block = {'dataActions': ['Microsoft.CognitiveServices/*'],
                 'notDataActions': ['Microsoft.CognitiveServices/accounts/delete']}
        self.assertTrue(permission_grants(block, ACTION))

    def test_control_plane_wildcard_grants_nothing(self):
        self.assertFalse(permission_grants({'actions': ['*'], 'dataActions': []}, ACTION))

    def test_missing_and_null_keys(self):
        self.assertFalse(permission_grants({}, ACTION))
        self.assertFalse(permission_grants({'dataActions': None, 'notDataActions': None}, ACTION))

    def test_not_data_action_never_grants(self):
        self.assertFalse(permission_grants({'notDataActions': [ACTION]}, ACTION))


class PermissionsGrantTest(unittest.TestCase):

    def test_second_block_can_grant_after_first_cancels(self):
        blocks = [
            {'dataActions': ['*'], 'notDataActions': [ACTION]},
            {'dataActions': [ACTION]},
        ]
        self.assertTrue(permissions_grant(blocks, ACTION))

    def test_no_blocks(self):
        self.assertFalse(permissions_grant([], ACTION))
        self.assertFalse(permissions_grant(None, ACTION))
