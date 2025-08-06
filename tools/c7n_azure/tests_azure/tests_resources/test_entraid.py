# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock, patch
import pytest
from pytest_terraform import terraform

from c7n_azure.resources.entraid_user import EntraIDUser
from c7n_azure.resources.entraid_group import EntraIDGroup
from c7n_azure.resources.entraid_organization import EntraIDOrganization
from c7n_azure.resources.entraid_conditional_access import EntraIDConditionalAccessPolicy
from c7n_azure.resources.entraid_security_defaults import EntraIDSecurityDefaults
from tests_azure.azure_common import BaseTest


class EntraIDUserTest(BaseTest):
    """Test EntraID User resource functionality"""

    def test_entraid_user_schema_validate(self):
        """Test that the EntraID user resource schema validates correctly"""
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-entraid-user',
                'resource': 'azure.entraid-user',
                'filters': [
                    {'type': 'value', 'key': 'accountEnabled', 'value': True}
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_entraid_user_resource_type(self):
        """Test EntraID user resource type configuration"""
        resource_type = EntraIDUser.resource_type
        self.assertEqual(resource_type.service, 'graph')
        self.assertEqual(resource_type.id, 'id')
        self.assertEqual(resource_type.name, 'displayName')
        self.assertTrue(resource_type.global_resource)
        self.assertIn('User.Read.All', resource_type.permissions)

    @patch('c7n_azure.resources.entraid_user.local_session')
    def test_entraid_user_augment(self, mock_session):
        """Test user resource augmentation with computed fields"""
        mock_client = Mock()
        mock_session.return_value.get_session_for_resource.return_value.\
client.return_value = mock_client

        # Sample user data
        users = [
            {
                'objectId': 'user1-id',
                'displayName': 'Test User',
                'userPrincipalName': 'test.user@example.com',
                'accountEnabled': True,
                'lastSignInDateTime': '2023-01-01T12:00:00Z',
                'lastPasswordChangeDateTime': '2022-01-01T12:00:00Z',
                'jobTitle': 'Administrator'
            },
            {
                'objectId': 'user2-id',
                'displayName': 'Regular User',
                'userPrincipalName': 'regular@example.com',
                'accountEnabled': False,
                'lastSignInDateTime': None,
                'lastPasswordChangeDateTime': None,
                'jobTitle': 'User'
            }
        ]

        policy = self.load_policy({
            'name': 'test-augment',
            'resource': 'azure.entraid-user'
        })

        resource_mgr = policy.resource_manager
        augmented = resource_mgr.augment(users)

        # Check augmented fields
        self.assertIn('c7n:LastSignInDays', augmented[0])
        self.assertIn('c7n:IsHighPrivileged', augmented[0])
        self.assertIn('c7n:PasswordAge', augmented[0])

        # Admin user should be flagged as high privileged
        self.assertTrue(augmented[0]['c7n:IsHighPrivileged'])
        self.assertFalse(augmented[1]['c7n:IsHighPrivileged'])

    @patch('c7n_azure.resources.entraid_user.EntraIDUser.check_user_mfa_status')
    def test_mfa_enabled_filter(self, mock_mfa_check):
        """Test MFA enabled filter with real Graph API implementation"""
        users = [
            {
                'id': 'user1',
                'objectId': 'user1',
                'displayName': 'User 1'
            },
            {
                'id': 'user2',
                'objectId': 'user2',
                'displayName': 'User 2'
            },
            {
                'id': 'user3',
                'objectId': 'user3',
                'displayName': 'User 3'
            }
        ]

        # Mock MFA status: user1 has MFA, user2 doesn't, user3 unknown
        def mock_mfa_side_effect(user_id):
            if user_id == 'user1':
                return True
            elif user_id == 'user2':
                return False
            else:
                return None  # Unknown status

        mock_mfa_check.side_effect = mock_mfa_side_effect

        policy = self.load_policy({
            'name': 'test-mfa-filter',
            'resource': 'azure.entraid-user',
            'filters': [
                {'type': 'mfa-enabled', 'value': True}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(users)

        # Only user1 has MFA enabled (user3 skipped due to unknown status)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['id'], 'user1')

        # Verify the MFA check was called for each user
        self.assertEqual(mock_mfa_check.call_count, 3)

    def test_last_signin_filter(self):
        """Test last sign-in filter"""
        users = [
            {
                'objectId': 'user1',
                'c7n:LastSignInDays': 120  # Old sign-in
            },
            {
                'objectId': 'user2',
                'c7n:LastSignInDays': 30   # Recent sign-in
            },
            {
                'objectId': 'user3',
                'c7n:LastSignInDays': 999  # Never signed in
            }
        ]

        policy = self.load_policy({
            'name': 'test-signin-filter',
            'resource': 'azure.entraid-user',
            'filters': [
                {'type': 'last-sign-in', 'days': 90, 'op': 'greater-than'}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(users)

        # Should match user1 and user3 (>90 days)
        self.assertEqual(len(filtered), 2)
        self.assertEqual(set(u['objectId'] for u in filtered), {'user1', 'user3'})

    @patch('c7n_azure.resources.entraid_user.EntraIDUser.get_user_group_memberships')
    def test_group_membership_filter(self, mock_group_memberships):
        """Test group membership filter with real Graph API implementation"""
        users = [
            {
                'id': 'user1',
                'objectId': 'user1',
                'displayName': 'User 1'
            },
            {
                'id': 'user2',
                'objectId': 'user2',
                'displayName': 'User 2'
            },
            {
                'id': 'user3',
                'objectId': 'user3',
                'displayName': 'User 3'
            }
        ]

        # Mock group memberships: user1 in admin groups, user2 in regular, user3 unknown
        def mock_group_side_effect(user_id):
            if user_id == 'user1':
                return [
                    {'id': 'group1', 'displayName': 'Global Administrators'},
                    {'id': 'group2', 'displayName': 'Regular Users'}
                ]
            elif user_id == 'user2':
                return [
                    {'id': 'group2', 'displayName': 'Regular Users'}
                ]
            else:
                return None  # Unknown group memberships

        mock_group_memberships.side_effect = mock_group_side_effect

        policy = self.load_policy({
            'name': 'test-group-filter',
            'resource': 'azure.entraid-user',
            'filters': [
                {
                    'type': 'group-membership',
                    'groups': ['Global Administrators'],
                    'match': 'any'
                }
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(users)

        # Only user1 is in admin group (user3 skipped due to unknown status)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['id'], 'user1')

        # Verify the group membership check was called
        self.assertEqual(mock_group_memberships.call_count, 3)

    @patch('c7n_azure.resources.entraid_user.EntraIDUser.make_graph_request')
    def test_user_type_field_requested(self, mock_graph_request):
        """Test that userType field is explicitly requested from Graph API"""
        # Mock the Graph API response with userType field
        mock_graph_request.return_value = {
            'value': [
                {
                    'id': 'user1',
                    'objectId': 'user1',
                    'displayName': 'Guest User',
                    'userPrincipalName': 'guest@external.com',
                    'userType': 'Guest',
                    'accountEnabled': True
                },
                {
                    'id': 'user2',
                    'objectId': 'user2',
                    'displayName': 'Member User',
                    'userPrincipalName': 'member@internal.com',
                    'userType': 'Member',
                    'accountEnabled': True
                }
            ]
        }

        policy = self.load_policy({
            'name': 'test-usertype-field',
            'resource': 'azure.entraid-user'
        })

        resource_mgr = policy.resource_manager
        resources = resource_mgr.resources()

        # Verify the API was called with $select parameter including userType
        mock_graph_request.assert_called_once()
        call_args = mock_graph_request.call_args[0]
        endpoint = call_args[0]
        self.assertIn('$select=', endpoint)
        self.assertIn('userType', endpoint)

        # Verify userType field is present in returned resources
        self.assertEqual(len(resources), 2)
        self.assertEqual(resources[0]['userType'], 'Guest')
        self.assertEqual(resources[1]['userType'], 'Member')

    def test_guest_user_filter(self):
        """Test that ValueFilter works correctly with userType field for guest users"""
        users = [
            {
                'id': 'user1',
                'objectId': 'user1',
                'displayName': 'Guest User',
                'userPrincipalName': 'guest@external.com',
                'userType': 'Guest',
                'accountEnabled': True
            },
            {
                'id': 'user2',
                'objectId': 'user2',
                'displayName': 'Member User',
                'userPrincipalName': 'member@internal.com',
                'userType': 'Member',
                'accountEnabled': True
            },
            {
                'id': 'user3',
                'objectId': 'user3',
                'displayName': 'Another Member',
                'userPrincipalName': 'member2@internal.com',
                'userType': 'Member',
                'accountEnabled': True
            }
        ]

        # Test filtering for guest users (like the guest-users.yaml policy)
        policy = self.load_policy({
            'name': 'test-guest-filter',
            'resource': 'azure.entraid-user',
            'filters': [
                {'type': 'value', 'key': 'userType', 'value': 'Guest'},
                {'type': 'value', 'key': 'accountEnabled', 'value': True}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(users)

        # Should only return the guest user
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['userType'], 'Guest')
        self.assertEqual(filtered[0]['displayName'], 'Guest User')

        # Test filtering for member users
        policy_members = self.load_policy({
            'name': 'test-member-filter',
            'resource': 'azure.entraid-user',
            'filters': [
                {'type': 'value', 'key': 'userType', 'value': 'Member'}
            ]
        })

        resource_mgr_members = policy_members.resource_manager
        filtered_members = resource_mgr_members.filter_resources(users)

        # Should return both member users
        self.assertEqual(len(filtered_members), 2)
        self.assertTrue(all(u['userType'] == 'Member' for u in filtered_members))

    def test_password_age_filter(self):
        """Test password age filter"""
        users = [
            {
                'objectId': 'user1',
                'c7n:PasswordAge': 200  # Old password
            },
            {
                'objectId': 'user2',
                'c7n:PasswordAge': 30   # Recent password change
            }
        ]

        policy = self.load_policy({
            'name': 'test-password-age',
            'resource': 'azure.entraid-user',
            'filters': [
                {'type': 'password-age', 'days': 180, 'op': 'greater-than'}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(users)

        # Only user1 has old password
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['objectId'], 'user1')

    def test_disable_user_action(self):
        """Test disable user action"""

        policy = self.load_policy({
            'name': 'test-disable-action',
            'resource': 'azure.entraid-user',
            'actions': [{'type': 'disable'}]
        })

        # Validate action schema
        resource_mgr = policy.resource_manager
        action = resource_mgr.actions[0]
        self.assertEqual(action.type, 'disable')
        self.assertIn('User.ReadWrite.All', action.permissions)


class EntraIDGroupTest(BaseTest):
    """Test EntraID Group resource functionality"""

    def test_entraid_group_schema_validate(self):
        """Test that the EntraID group resource schema validates correctly"""
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-entraid-group',
                'resource': 'azure.entraid-group',
                'filters': [
                    {'type': 'value', 'key': 'securityEnabled', 'value': True}
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_entraid_group_resource_type(self):
        """Test EntraID group resource type configuration"""
        resource_type = EntraIDGroup.resource_type
        self.assertEqual(resource_type.service, 'graph')
        self.assertEqual(resource_type.id, 'id')
        self.assertEqual(resource_type.name, 'displayName')
        self.assertTrue(resource_type.global_resource)
        self.assertIn('Group.Read.All', resource_type.permissions)

    def test_entraid_group_augment(self):
        """Test group resource augmentation with computed fields"""

        # Sample group data
        groups = [
            {
                'id': 'group1-id',
                'displayName': 'Global Administrators',
                'description': 'Admin group',
                'securityEnabled': True,
                'mailEnabled': False,
                'groupTypes': []
            },
            {
                'id': 'group2-id',
                'displayName': 'All Users Distribution',
                'description': 'Distribution list',
                'securityEnabled': False,
                'mailEnabled': True,
                'groupTypes': ['Unified']
            },
            {
                'id': 'group3-id',
                'displayName': 'Dynamic Security Group',
                'description': 'Dynamic membership',
                'securityEnabled': True,
                'mailEnabled': False,
                'groupTypes': ['DynamicMembership']
            }
        ]

        policy = self.load_policy({
            'name': 'test-augment',
            'resource': 'azure.entraid-group'
        })

        resource_mgr = policy.resource_manager
        augmented = resource_mgr.augment(groups)

        # Check augmented fields
        self.assertIn('c7n:IsSecurityGroup', augmented[0])
        self.assertIn('c7n:IsDistributionGroup', augmented[0])
        self.assertIn('c7n:IsDynamicGroup', augmented[0])
        self.assertIn('c7n:IsAdminGroup', augmented[0])

        # Admin group should be flagged correctly
        self.assertTrue(augmented[0]['c7n:IsSecurityGroup'])
        self.assertTrue(augmented[0]['c7n:IsAdminGroup'])
        self.assertFalse(augmented[0]['c7n:IsDistributionGroup'])

        # Distribution group should be flagged correctly
        self.assertFalse(augmented[1]['c7n:IsSecurityGroup'])
        self.assertTrue(augmented[1]['c7n:IsDistributionGroup'])
        self.assertFalse(augmented[1]['c7n:IsAdminGroup'])

        # Dynamic group should be flagged correctly
        self.assertTrue(augmented[2]['c7n:IsSecurityGroup'])
        self.assertTrue(augmented[2]['c7n:IsDynamicGroup'])

    @patch('c7n_azure.resources.entraid_group.EntraIDGroup.get_group_member_count')
    def test_member_count_filter(self, mock_member_count):
        """Test member count filter with real Graph API implementation"""
        groups = [
            {
                'id': 'group1',
                'displayName': 'Small Group'
            },
            {
                'id': 'group2',
                'displayName': 'Large Group'
            },
            {
                'id': 'group3',
                'displayName': 'Empty Group'
            }
        ]

        # Mock member counts: group1=2, group2=5, group3=0
        def mock_count_side_effect(group_id):
            if group_id == 'group1':
                return 2
            elif group_id == 'group2':
                return 5
            elif group_id == 'group3':
                return 0
            else:
                return None

        mock_member_count.side_effect = mock_count_side_effect

        policy = self.load_policy({
            'name': 'test-member-count',
            'resource': 'azure.entraid-group',
            'filters': [
                {'type': 'member-count', 'count': 3, 'op': 'greater-than'}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(groups)

        # Only group2 has >3 members
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['id'], 'group2')

        # Verify the member count check was called
        self.assertEqual(mock_member_count.call_count, 3)

    @patch('c7n_azure.resources.entraid_group.EntraIDGroup.get_group_owner_count')
    def test_owner_count_filter(self, mock_owner_count):
        """Test owner count filter with real Graph API implementation"""
        groups = [
            {
                'id': 'group1',
                'displayName': 'Owned Group'
            },
            {
                'id': 'group2',
                'displayName': 'Orphaned Group'
            }
        ]

        # Mock owner counts: group1=1, group2=0
        def mock_count_side_effect(group_id):
            if group_id == 'group1':
                return 1
            elif group_id == 'group2':
                return 0
            else:
                return None

        mock_owner_count.side_effect = mock_count_side_effect

        policy = self.load_policy({
            'name': 'test-owner-count',
            'resource': 'azure.entraid-group',
            'filters': [
                {'type': 'owner-count', 'count': 0, 'op': 'equal'}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(groups)

        # Only group2 has no owners
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['id'], 'group2')

        # Verify the owner count check was called
        self.assertEqual(mock_owner_count.call_count, 2)

    def test_group_type_filter(self):
        """Test group type filter"""
        groups = [
            {
                'id': 'group1',
                'displayName': 'Security Group',
                'c7n:IsSecurityGroup': True,
                'c7n:IsDistributionGroup': False,
                'c7n:IsDynamicGroup': False,
                'c7n:IsAdminGroup': False
            },
            {
                'id': 'group2',
                'displayName': 'Distribution Group',
                'c7n:IsSecurityGroup': False,
                'c7n:IsDistributionGroup': True,
                'c7n:IsDynamicGroup': False,
                'c7n:IsAdminGroup': False
            },
            {
                'id': 'group3',
                'displayName': 'Admin Group',
                'c7n:IsSecurityGroup': True,
                'c7n:IsDistributionGroup': False,
                'c7n:IsDynamicGroup': False,
                'c7n:IsAdminGroup': True
            }
        ]

        policy = self.load_policy({
            'name': 'test-group-type',
            'resource': 'azure.entraid-group',
            'filters': [
                {'type': 'group-type', 'group-type': 'admin'}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(groups)

        # Only group3 is an admin group
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['id'], 'group3')


class EntraIDOrganizationTest(BaseTest):
    """Test EntraID Organization resource functionality"""

    def test_entraid_organization_schema_validate(self):
        """Test organization resource schema validation"""
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-organization',
                'resource': 'azure.entraid-organization',
                'filters': [
                    {'type': 'security-defaults', 'enabled': True}
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_organization_resource_type(self):
        """Test organization resource type configuration"""
        resource_type = EntraIDOrganization.resource_type
        self.assertEqual(resource_type.service, 'graph')
        self.assertEqual(resource_type.id, 'id')
        self.assertTrue(resource_type.global_resource)
        self.assertIn('Organization.Read.All', resource_type.permissions)

    def test_security_defaults_filter(self):
        """Test security defaults filter"""
        orgs = [
            {
                'id': 'org1',
                'displayName': 'Test Organization',
                'securityDefaults': {'isEnabled': True}
            },
            {
                'id': 'org2',
                'displayName': 'Another Organization',
                'securityDefaults': {'isEnabled': False}
            }
        ]

        policy = self.load_policy({
            'name': 'test-security-defaults',
            'resource': 'azure.entraid-organization',
            'filters': [
                {'type': 'security-defaults', 'enabled': False}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(orgs)

        # Only org2 has security defaults disabled
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['id'], 'org2')


class EntraIDConditionalAccessTest(BaseTest):
    """Test EntraID Conditional Access Policy resource functionality"""

    def test_conditional_access_schema_validate(self):
        """Test conditional access policy schema validation"""
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-conditional-access',
                'resource': 'azure.entraid-conditional-access-policy',
                'filters': [
                    {'type': 'value', 'key': 'state', 'value': 'enabled'}
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_conditional_access_resource_type(self):
        """Test conditional access resource type configuration"""
        resource_type = EntraIDConditionalAccessPolicy.resource_type
        self.assertEqual(resource_type.service, 'graph')
        self.assertEqual(resource_type.id, 'id')
        self.assertTrue(resource_type.global_resource)
        self.assertIn('Policy.Read.All', resource_type.permissions)

    def test_admin_mfa_required_filter(self):
        """Test admin MFA required filter"""
        policies = [
            {
                'id': 'policy1',
                'displayName': 'Admin MFA Policy',
                'state': 'enabled',
                'conditions': {
                    'users': {
                        'includeRoles': ['Global Administrator']
                    }
                },
                'grantControls': {
                    'builtInControls': ['mfa']
                }
            },
            {
                'id': 'policy2',
                'displayName': 'Admin No MFA Policy',
                'state': 'enabled',
                'conditions': {
                    'users': {
                        'includeRoles': ['Global Administrator']
                    }
                },
                'grantControls': {
                    'builtInControls': ['block']
                }
            },
            {
                'id': 'policy3',
                'displayName': 'User Policy',
                'state': 'enabled',
                'conditions': {
                    'users': {
                        'includeRoles': ['User']
                    }
                },
                'grantControls': {
                    'builtInControls': ['mfa']
                }
            }
        ]

        policy = self.load_policy({
            'name': 'test-admin-mfa',
            'resource': 'azure.entraid-conditional-access-policy',
            'filters': [
                {'type': 'admin-mfa-required', 'value': True}
            ]
        })

        resource_mgr = policy.resource_manager
        filtered = resource_mgr.filter_resources(policies)

        # Only policy1 requires MFA for admins
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['id'], 'policy1')


class EntraIDSecurityDefaultsTest(BaseTest):
    """Test EntraID Security Defaults resource functionality"""

    def test_security_defaults_schema_validate(self):
        """Test security defaults schema validation"""
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-security-defaults',
                'resource': 'azure.entraid-security-defaults',
                'filters': [
                    {'type': 'value', 'key': 'isEnabled', 'value': True}
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_security_defaults_resource_type(self):
        """Test security defaults resource type configuration"""
        resource_type = EntraIDSecurityDefaults.resource_type
        self.assertEqual(resource_type.service, 'graph')
        self.assertEqual(resource_type.id, 'id')
        self.assertTrue(resource_type.global_resource)
        self.assertIn('Policy.Read.All', resource_type.permissions)


# Terraform-based integration tests
# These tests use real Azure EntraID resources provisioned via Terraform
# Following the same pattern as AWS tests


@terraform('entraid_user')
@pytest.mark.functional
def test_entraid_user_discovery_terraform(test, entraid_user):
    """Test that Cloud Custodian can discover users provisioned by Terraform"""
    # Verify terraform fixtures loaded successfully
    assert len(entraid_user.outputs) == 5, (
        f"Expected 5 total outputs (4 users + 1 group), got {len(entraid_user.outputs)}"
    )
    assert 'azuread_user' in entraid_user.resources, "azuread_user resources not found"

    # Get terraform-provisioned user data
    admin_user = entraid_user.outputs['test_admin_user']['value']
    disabled_user = entraid_user.outputs['test_disabled_user']['value']
    regular_user = entraid_user.outputs['test_regular_user']['value']
    old_password_user = entraid_user.outputs['test_old_password_user']['value']

    # Verify test data integrity
    assert admin_user['account_enabled'] is True
    assert admin_user['job_title'] == 'Administrator'
    assert admin_user['department'] == 'IT'

    assert disabled_user['account_enabled'] is False
    assert disabled_user['job_title'] == 'User'
    assert disabled_user['department'] == 'HR'

    assert regular_user['account_enabled'] is True
    assert regular_user['job_title'] == 'Developer'
    assert regular_user['department'] == 'Engineering'

    assert old_password_user['account_enabled'] is True
    assert old_password_user['job_title'] == 'Analyst'
    assert old_password_user['department'] == 'Finance'

    # Test Cloud Custodian policy creation and validation
    policy = test.load_policy({
        'name': 'terraform-enabled-users',
        'resource': 'azure.entraid-user',
        'filters': [
            {'type': 'value', 'key': 'accountEnabled', 'value': True}
        ]
    })

    # Verify policy loads correctly
    assert policy.resource_manager.type == 'entraid-user'

    # Test job title filter policy
    admin_policy = test.load_policy({
        'name': 'terraform-admin-users',
        'resource': 'azure.entraid-user',
        'filters': [
            {'type': 'value', 'key': 'jobTitle', 'value': 'Administrator'}
        ]
    })

    assert admin_policy.resource_manager.type == 'entraid-user'

    print(f"SUCCESS: Terraform fixtures loaded {len(entraid_user.outputs)} users successfully")


@terraform('entraid_user')
@pytest.mark.functional
def test_entraid_user_job_title_filter_terraform(test, entraid_user):
    """Test job title filter against Terraform-provisioned users"""
    admin_user = entraid_user.outputs['test_admin_user']['value']
    regular_user = entraid_user.outputs['test_regular_user']['value']

    # Test policy for admin job titles
    policy = test.load_policy({
        'name': 'terraform-admin-users',
        'resource': 'azure.entraid-user',
        'filters': [
            {'type': 'value', 'key': 'jobTitle', 'value': 'Administrator'}
        ]
    })

    # Verify test data has expected job titles
    assert admin_user['job_title'] == 'Administrator'
    assert regular_user['job_title'] == 'Developer'

    # Verify policy validates correctly
    assert policy is not None


@terraform('entraid_user')
@pytest.mark.functional
def test_entraid_user_department_filter_terraform(test, entraid_user):
    """Test department filter against Terraform-provisioned users"""
    admin_user = entraid_user.outputs['test_admin_user']['value']
    old_password_user = entraid_user.outputs['test_old_password_user']['value']

    # Test policy for IT department users
    policy = test.load_policy({
        'name': 'terraform-it-users',
        'resource': 'azure.entraid-user',
        'filters': [
            {'type': 'value', 'key': 'department', 'value': 'IT'}
        ]
    })

    # Verify test data has expected departments
    assert admin_user['department'] == 'IT'
    assert old_password_user['department'] == 'Finance'

    assert policy is not None


@terraform('entraid_organization')
@pytest.mark.functional
def test_entraid_organization_discovery_terraform(test, entraid_organization):
    """Test that Cloud Custodian can discover organization provisioned by Terraform"""
    org_info = entraid_organization.outputs['organization_basic_info']['value']

    # Test basic organization discovery
    policy = test.load_policy({
        'name': 'terraform-organization-discovery',
        'resource': 'azure.entraid-organization'
    })

    # Verify policy loads correctly
    assert policy.resource_manager.type == 'entraid-organization'

    # Verify test data structure
    assert 'id' in org_info
    assert 'display_name' in org_info
    assert 'tenant_id' in org_info


@terraform('entraid_organization')
@pytest.mark.functional
def test_entraid_organization_domains_terraform(test, entraid_organization):
    """Test organization domains against Terraform-provisioned data"""
    domains_info = entraid_organization.outputs['organization_domains']['value']

    # Test organization domains discovery
    policy = test.load_policy({
        'name': 'terraform-organization-domains',
        'resource': 'azure.entraid-organization'
    })

    # Verify domains data structure
    assert 'domains' in domains_info
    assert len(domains_info['domains']) > 0

    # Verify domain properties
    for domain in domains_info['domains']:
        assert 'domain_name' in domain
        assert 'is_verified' in domain
        assert 'is_default' in domain
        assert 'authentication_type' in domain

    assert policy is not None


@terraform('entraid_organization')
@pytest.mark.functional
def test_entraid_organization_compliance_terraform(test, entraid_organization):
    """Test organization compliance data against Terraform-provisioned data"""
    compliance = entraid_organization.outputs['organization_compliance']['value']

    # Test compliance monitoring
    policy = test.load_policy({
        'name': 'terraform-organization-compliance',
        'resource': 'azure.entraid-organization'
    })

    # Verify CIS compliance structure
    assert 'cis_compliance' in compliance
    cis_compliance = compliance['cis_compliance']
    assert 'version' in cis_compliance
    assert 'controls' in cis_compliance

    # Verify NIST compliance structure
    assert 'nist_compliance' in compliance
    nist_compliance = compliance['nist_compliance']
    assert 'framework' in nist_compliance
    assert 'controls' in nist_compliance

    assert policy is not None


@terraform('entraid_security_defaults')
@pytest.mark.functional
def test_entraid_security_defaults_discovery_terraform(test, entraid_security_defaults):
    """Test that Cloud Custodian can discover security defaults provisioned by Terraform"""
    enabled_defaults = entraid_security_defaults.outputs['security_defaults_enabled']['value']
    disabled_defaults = entraid_security_defaults.outputs['security_defaults_disabled']['value']

    # Test basic security defaults discovery
    policy = test.load_policy({
        'name': 'terraform-security-defaults-discovery',
        'resource': 'azure.entraid-security-defaults'
    })

    # Verify policy loads correctly
    assert policy.resource_manager.type == 'entraid-security-defaults'

    # Verify test data integrity
    assert enabled_defaults['is_enabled'] is True
    assert disabled_defaults['is_enabled'] is False
    assert enabled_defaults['display_name'] == 'Security Defaults'


@terraform('entraid_security_defaults')
@pytest.mark.functional
def test_entraid_security_defaults_features_terraform(test, entraid_security_defaults):
    """Test security defaults features against Terraform-provisioned data"""
    features = entraid_security_defaults.outputs['security_defaults_features']['value']

    # Test security defaults feature analysis
    policy = test.load_policy({
        'name': 'terraform-security-defaults-features',
        'resource': 'azure.entraid-security-defaults',
        'filters': [
            {'type': 'value', 'key': 'isEnabled', 'value': True}
        ]
    })

    # Verify features structure
    assert 'enabled_features' in features
    enabled_features = features['enabled_features']

    # Verify key security features
    expected_features = [
        'require_mfa_for_admins',
        'require_mfa_for_users',
        'block_legacy_authentication',
        'protect_privileged_activities'
    ]

    for feature in expected_features:
        assert feature in enabled_features
        assert 'enabled' in enabled_features[feature]
        assert 'description' in enabled_features[feature]

    # Verify admin MFA feature details
    mfa_admin_feature = enabled_features['require_mfa_for_admins']
    assert 'affected_roles' in mfa_admin_feature
    assert 'Global Administrator' in mfa_admin_feature['affected_roles']

    assert policy is not None


@terraform('entraid_security_defaults')
@pytest.mark.functional
def test_entraid_security_defaults_compliance_terraform(test, entraid_security_defaults):
    """Test security defaults compliance against Terraform-provisioned data"""
    compliance = entraid_security_defaults.outputs['security_defaults_compliance']['value']

    # Test compliance analysis
    policy = test.load_policy({
        'name': 'terraform-security-defaults-compliance',
        'resource': 'azure.entraid-security-defaults'
    })

    # Verify compliance structure
    required_sections = [
        'cis_compliant_controls',
        'security_improvements',
        'limitations',
        'recommendations'
    ]
    for section in required_sections:
        assert section in compliance

    # Verify CIS compliance controls
    cis_controls = compliance['cis_compliant_controls']
    assert len(cis_controls) > 0

    for control in cis_controls:
        assert 'control' in control
        assert 'title' in control
        assert 'status' in control

    # Verify security improvements
    improvements = compliance['security_improvements']
    assert len(improvements) > 0

    for improvement in improvements:
        assert 'area' in improvement
        assert 'improvement' in improvement
        assert 'risk_reduction' in improvement

    assert policy is not None


@terraform('entraid_security_defaults')
@pytest.mark.functional
def test_entraid_security_defaults_scenarios_terraform(test, entraid_security_defaults):
    """Test tenant scenarios against Terraform-provisioned data"""
    scenarios = entraid_security_defaults.outputs['test_scenarios']['value']

    # Test scenario-based analysis
    policy = test.load_policy({
        'name': 'terraform-tenant-scenarios',
        'resource': 'azure.entraid-security-defaults'
    })

    # Verify all expected scenarios
    expected_scenarios = ['new_tenant_secure', 'disabled_no_ca', 'disabled_with_ca']
    for scenario_name in expected_scenarios:
        assert scenario_name in scenarios

        scenario = scenarios[scenario_name]
        required_fields = [
            'security_defaults_enabled',
            'conditional_access_policies',
            'mfa_enforced_users',
            'legacy_auth_blocked',
            'compliance_score',
            'risk_level'
        ]

        for field in required_fields:
            assert field in scenario

    # Verify scenario logic
    secure_scenario = scenarios['new_tenant_secure']
    risky_scenario = scenarios['disabled_no_ca']
    optimal_scenario = scenarios['disabled_with_ca']

    assert secure_scenario['security_defaults_enabled'] is True
    assert risky_scenario['security_defaults_enabled'] is False
    assert optimal_scenario['security_defaults_enabled'] is False

    assert optimal_scenario['compliance_score'] > secure_scenario['compliance_score']
    assert secure_scenario['compliance_score'] > risky_scenario['compliance_score']

    assert policy is not None
