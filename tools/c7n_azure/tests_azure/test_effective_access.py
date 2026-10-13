# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest import mock

import requests
from c7n_azure.effective_access import (
    ALL_PRINCIPALS,
    access_paths,
    action_matches,
    classify,
    deny_applies,
    members_approved,
    permission_grants,
    permissions_grant,
    transitive_members,
)
from c7n_azure.graph_utils import get_required_permissions_for_endpoint

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


ROLE_ID = '/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/r-user'
ADMIN_ROLE_ID = '/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/r-admin'
READER_ROLE_ID = '/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/r-reader'
RG_SCOPE = '/subscriptions/s1/resourceGroups/rg'
USER = '11111111-1111-1111-1111-111111111111'
OTHER = '22222222-2222-2222-2222-222222222222'
GROUP = '33333333-3333-3333-3333-333333333333'


def role(role_id, name, *permissions):
    return {'id': role_id, 'properties': {'roleName': name, 'permissions': list(permissions)}}


def assignment(aid, role_id, principal_id, principal_type='User', scope=SCOPE, condition=None):
    return {'id': aid,
            'properties': {'roleDefinitionId': role_id, 'principalId': principal_id,
                           'principalType': principal_type, 'scope': scope,
                           'condition': condition}}


def deny(principals, permissions=None, scope=SCOPE, exclude=(), no_children=False,
         condition=None):
    return {'properties': {
        'scope': scope,
        'doNotApplyToChildScopes': no_children,
        'condition': condition,
        'principals': [{'id': p, 'type': 'User'} for p in principals],
        'excludePrincipals': [{'id': p, 'type': 'User'} for p in exclude],
        'permissions': permissions if permissions is not None else [{'dataActions': [ACTION]}]}}


ROLES = {
    ROLE_ID.lower(): role(ROLE_ID, 'Cognitive Services OpenAI User', {'dataActions': [ACTION]}),
    ADMIN_ROLE_ID.lower(): role(ADMIN_ROLE_ID, 'Owner', {'actions': ['*'], 'dataActions': []}),
    READER_ROLE_ID.lower(): role(
        READER_ROLE_ID, 'Reader', {'dataActions': ['*'], 'notDataActions': [ACTION]}),
}


class DenyAppliesTest(unittest.TestCase):

    def test_all_principals_guid(self):
        self.assertTrue(deny_applies(deny([ALL_PRINCIPALS]), SCOPE, USER, ACTION))

    def test_named_principal_case_insensitive(self):
        d = deny([USER.upper()])
        self.assertTrue(deny_applies(d, SCOPE, USER.lower(), ACTION))
        self.assertFalse(deny_applies(d, SCOPE, OTHER, ACTION))

    def test_excluded_principal_is_not_denied(self):
        d = deny([ALL_PRINCIPALS], exclude=[USER])
        self.assertFalse(deny_applies(d, SCOPE, USER, ACTION))
        self.assertTrue(deny_applies(d, SCOPE, OTHER, ACTION))

    def test_conditional_deny_is_not_subtracted(self):
        self.assertFalse(
            deny_applies(deny([ALL_PRINCIPALS], condition='@Resource[x] == 1'),
                         SCOPE, USER, ACTION))

    def test_do_not_apply_to_child_scopes(self):
        parent = deny([ALL_PRINCIPALS], scope=RG_SCOPE, no_children=True)
        self.assertFalse(deny_applies(parent, SCOPE, USER, ACTION))
        same = deny([ALL_PRINCIPALS], scope=SCOPE, no_children=True)
        self.assertTrue(deny_applies(same, SCOPE, USER, ACTION))

    def test_inheriting_deny_from_parent_scope(self):
        self.assertTrue(
            deny_applies(deny([ALL_PRINCIPALS], scope=RG_SCOPE), SCOPE, USER, ACTION))

    def test_deny_not_data_actions_exempt_the_action(self):
        d = deny([ALL_PRINCIPALS],
                 permissions=[{'dataActions': ['*'], 'notDataActions': [ACTION]}])
        self.assertFalse(deny_applies(d, SCOPE, USER, ACTION))

    def test_deny_for_other_action(self):
        d = deny([ALL_PRINCIPALS], permissions=[{'dataActions': ['Microsoft.Storage/*']}])
        self.assertFalse(deny_applies(d, SCOPE, USER, ACTION))


class AccessPathsTest(unittest.TestCase):

    def test_granting_assignment_becomes_path(self):
        paths = access_paths([assignment('a1', ROLE_ID, USER)], ROLES, [], SCOPE, ACTION)
        self.assertEqual(paths, [{
            'assignmentId': 'a1', 'scope': SCOPE,
            'roleName': 'Cognitive Services OpenAI User',
            'principalId': USER, 'principalType': 'User', 'condition': None}])

    def test_no_assignments(self):
        self.assertEqual(access_paths([], ROLES, [], SCOPE, ACTION), [])

    def test_control_plane_owner_and_notdataactions_reader_grant_nothing(self):
        paths = access_paths(
            [assignment('a1', ADMIN_ROLE_ID, USER), assignment('a2', READER_ROLE_ID, OTHER)],
            ROLES, [], SCOPE, ACTION)
        self.assertEqual(paths, [])

    def test_same_principal_two_assignments_gives_two_paths(self):
        paths = access_paths(
            [assignment('a1', ROLE_ID, USER), assignment('a2', ROLE_ID, USER, scope=RG_SCOPE)],
            ROLES, [], SCOPE, ACTION)
        self.assertEqual([p['assignmentId'] for p in paths], ['a1', 'a2'])

    def test_role_definition_lookup_ignores_case(self):
        paths = access_paths([assignment('a1', ROLE_ID.upper(), USER)], ROLES, [], SCOPE, ACTION)
        self.assertEqual(len(paths), 1)

    def test_deny_removes_path(self):
        paths = access_paths(
            [assignment('a1', ROLE_ID, USER), assignment('a2', ROLE_ID, OTHER)],
            ROLES, [deny([USER])], SCOPE, ACTION)
        self.assertEqual([p['principalId'] for p in paths], [OTHER])

    def test_condition_is_recorded(self):
        paths = access_paths(
            [assignment('a1', ROLE_ID, USER, condition='cond')], ROLES, [], SCOPE, ACTION)
        self.assertEqual(paths[0]['condition'], 'cond')

    def test_missing_role_definition_raises(self):
        with self.assertRaises(KeyError):
            access_paths([assignment('a1', '/missing/role', USER)], ROLES, [], SCOPE, ACTION)


class ClassifyTest(unittest.TestCase):

    def paths(self):
        return [
            {'principalId': USER, 'principalType': 'User'},
            {'principalId': GROUP, 'principalType': 'Group'},
            {'principalId': OTHER, 'principalType': 'ServicePrincipal'},
        ]

    def test_empty_approved_lists_flag_everyone(self):
        approved, unapproved = classify(self.paths(), [], [])
        self.assertEqual((len(approved), len(unapproved)), (0, 3))

    def test_approved_principal_and_group(self):
        approved, unapproved = classify(self.paths(), [GROUP], [USER])
        self.assertEqual([p['principalId'] for p in approved], [USER, GROUP])
        self.assertEqual([p['principalId'] for p in unapproved], [OTHER])

    def test_group_id_does_not_approve_a_user(self):
        approved, unapproved = classify(
            [{'principalId': USER, 'principalType': 'User'}], [USER], [])
        self.assertEqual((len(approved), len(unapproved)), (0, 1))

    def test_comparison_ignores_case(self):
        approved, _ = classify(self.paths(), [GROUP.upper()], [USER.upper()])
        self.assertEqual(len(approved), 2)


class MembersApprovedTest(unittest.TestCase):

    def member(self, oid, kind='user'):
        return {'@odata.type': '#microsoft.graph.' + kind, 'id': oid}

    def test_all_members_approved(self):
        members = [self.member(USER), self.member(OTHER, 'servicePrincipal')]
        self.assertTrue(members_approved(members, [USER, OTHER.upper()]))

    def test_one_stranger_blocks_approval(self):
        self.assertFalse(members_approved([self.member(USER), self.member(OTHER)], [USER]))

    def test_nested_group_objects_are_ignored(self):
        members = [self.member(USER), self.member(GROUP, 'group')]
        self.assertTrue(members_approved(members, [USER]))

    def test_empty_group_is_approved(self):
        self.assertTrue(members_approved([], []))


class GraphPermissionTest(unittest.TestCase):

    def test_transitive_members_maps_to_least_privilege(self):
        self.assertEqual(
            get_required_permissions_for_endpoint('groups/%s/transitiveMembers' % GROUP),
            ['GroupMember.ReadBasic.All'])


class TransitiveMembersTest(unittest.TestCase):
    """Control flow only. The recorded functional test pins the response shape."""

    def session(self):
        graph = mock.Mock()
        graph.credentials.get_token.return_value = mock.Mock(token='t')
        session = mock.Mock()
        session.get_session_for_resource.return_value = graph
        return session

    def response(self, payload, status=200):
        r = mock.Mock(status_code=status)
        r.json.return_value = payload
        if status >= 400:
            r.raise_for_status.side_effect = requests.HTTPError(response=r)
        return r

    def test_follows_next_link(self):
        pages = [
            self.response({'value': [{'id': 'a'}], '@odata.nextLink': 'https://next'}),
            self.response({'value': [{'id': 'b'}]}),
        ]
        with mock.patch('c7n_azure.effective_access.requests.get', side_effect=pages) as get:
            members = transitive_members(self.session(), GROUP)
        self.assertEqual([m['id'] for m in members], ['a', 'b'])
        self.assertEqual(get.call_args_list[1][0][0], 'https://next')
        self.assertIsNone(get.call_args_list[1][1]['params'])

    def test_403_raises_and_names_the_permission(self):
        with mock.patch('c7n_azure.effective_access.requests.get',
                        return_value=self.response({}, status=403)):
            with self.assertLogs('custodian.azure.effective_access', 'ERROR') as logs:
                with self.assertRaises(requests.HTTPError):
                    transitive_members(self.session(), GROUP)
        self.assertIn('GroupMember.ReadBasic.All', logs.output[0])
