# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import time
from unittest import mock

from gcp_common import BaseTest, event_data
from googleapiclient.errors import HttpError


class ProjectRoleTest(BaseTest):
    def test_get(self):
        factory = self.replay_flight_data("iam-project-role")

        p = self.load_policy(
            {
                "name": "role-get",
                "resource": "gcp.project-role",
                "mode": {"type": "gcp-audit", "methods": ["google.iam.admin.v1.CreateRole"]},
            },
            session_factory=factory,
        )

        exec_mode = p.get_execution_mode()
        event = event_data("iam-role-create.json")
        roles = exec_mode.run(event, None)

        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]["name"], "projects/cloud-custodian/roles/CustomRole1")

        self.assertEqual(
            p.resource_manager.get_urns(roles),
            ["gcp:iam::cloud-custodian:project-role/CustomRole1"],
        )


class ServiceAccountTest(BaseTest):
    def test_get(self):
        factory = self.replay_flight_data("iam-service-account")
        p = self.load_policy(
            {"name": "sa-get", "resource": "gcp.service-account"}, session_factory=factory
        )
        resource = p.resource_manager.get_resource(
            {
                "project_id": "cloud-custodian",
                # NOTE: flight data doesn't use this email_id.
                "email_id": "devtest@cloud-custodian.iam.gserviceaccount.com",
                # NOTE: unique_id not used at all in the get method.
                "unique_id": "110936229421407410679",
            }
        )
        self.assertEqual(resource["displayName"], "devtest")
        self.assertEqual(
            p.resource_manager.get_urns([resource]),
            [
                # NOTE: compare 'custodian-1291' with email given above.
                "gcp:iam::cloud-custodian:service-account/devtest@custodian-1291.iam.gserviceaccount.com"  # noqa: E501
            ],
        )

    def test_disable(self):
        factory = self.replay_flight_data("iam-service-account-disable")
        p = self.load_policy(
            {"name": "sa-disable", "resource": "gcp.service-account", "actions": ["disable"]},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        if self.recording:
            time.sleep(1)
        client = p.resource_manager.get_client()
        result = client.execute_query("get", {"name": resources[0]["name"]})
        self.assertTrue(result["disabled"])

    def test_enable(self):
        factory = self.replay_flight_data("iam-service-account-enable")
        p = self.load_policy(
            {"name": "sa-enable", "resource": "gcp.service-account", "actions": ["enable"]},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        if self.recording:
            time.sleep(1)
        client = p.resource_manager.get_client()
        result = client.execute_query("get", {"name": resources[0]["name"]})
        self.assertIsNone(result.get("disabled"))

    def test_delete(self):
        factory = self.replay_flight_data("iam-service-account-delete")
        p = self.load_policy(
            {"name": "sa-delete", "resource": "gcp.service-account", "actions": ["delete"]},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        if self.recording:
            time.sleep(1)
        client = p.resource_manager.get_client()
        try:
            client.execute_query("get", {"name": resources[0]["name"]})
            self.fail("found deleted service account")
        except HttpError as e:
            self.assertTrue("Account deleted" in str(e))

    def test_iam_policy_filter_match(self):
        factory = self.replay_flight_data("iam-service-account-iam-policy")
        p1 = self.load_policy(
            {
                "name": "sa-iam-policy",
                "resource": "gcp.service-account",
                "filters": [
                    {
                        "type": "iam-policy",
                        "doc": {
                            "key": "bindings[?(role=='roles/iam.serviceAccountTest1')].members[]",
                            "value_path": "bindings[?(role=='roles/iam.serviceAccountTest2')].members[]",  # noqa: E501
                            "op": "intersect",
                        },
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p1.run()
        self.assertEqual(len(resources), 1)

    def test_iam_policy_filter_multi_match(self):
        factory = self.replay_flight_data("iam-service-account-iam-policy-multi")
        p1 = self.load_policy(
            {
                "name": "sa-iam-policy",
                "resource": "gcp.service-account",
                "filters": [
                    {
                        "type": "iam-policy",
                        "doc": {
                            "key": "bindings[?(role=='roles/iam.serviceAccountTest1')].members[]",
                            "value_path": "bindings[?(role=='roles/iam.serviceAccountTest2')].members[]",  # noqa: E501
                            "op": "intersect",
                        },
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p1.run()
        self.assertEqual(len(resources), 4)

    def test_iam_policy_filter_no_match(self):
        factory = self.replay_flight_data("iam-service-account-iam-policy")
        p1 = self.load_policy(
            {
                "name": "sa-iam-policy",
                "resource": "gcp.service-account",
                "filters": [
                    {
                        "type": "iam-policy",
                        "doc": {
                            "key": "bindings[?(role=='roles/iam.serviceAccountTest1')].members[]",
                            "value_path": "bindings[?(role=='roles/iam.serviceAccountTest3')].members[]",  # noqa: E501
                            "op": "intersect",
                        },
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p1.run()
        self.assertEqual(len(resources), 0)


class ServiceAccountKeyTest(BaseTest):
    def test_service_account_key_query(self):
        project_id = "cloud-custodian"

        session_factory = self.replay_flight_data("iam-service-account-key-query", project_id)

        policy = self.load_policy(
            {"name": "iam-service-account-key-query", "resource": "gcp.service-account-key"},
            session_factory=session_factory,
        )

        resources = policy.run()
        self.assertEqual(len(resources), 2)
        self.assertEqual(resources[0]["keyType"], "SYSTEM_MANAGED")
        self.assertEqual(resources[1]["keyType"], "USER_MANAGED")
        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [
                "gcp:iam::cloud-custodian:service-account-key/test-cutodian-scc@cloud-custodian.iam.gserviceaccount.com/1",  # noqa: E501
                "gcp:iam::cloud-custodian:service-account-key/test-cutodian-scc@cloud-custodian.iam.gserviceaccount.com/2",  # noqa: E501
            ],
        )

    def test_get_service_account_key(self):
        factory = self.replay_flight_data("iam-service-account-key")
        p = self.load_policy(
            {"name": "sa-key-get", "resource": "gcp.service-account-key"}, session_factory=factory
        )
        resource = p.resource_manager.get_resource(
            {
                "resourceName": "//iam.googleapis.com/projects/cloud-custodian/"
                "serviceAccounts/111111111111111/keys/2222"
            }
        )
        self.assertEqual(resource["keyType"], "USER_MANAGED")
        self.assertEqual(
            resource["c7n:service-account"]["email"],
            "test-cutodian-scc@cloud-custodian.iam.gserviceaccount.com",
        )
        self.assertEqual(
            p.resource_manager.get_urns([resource]),
            [
                "gcp:iam::cloud-custodian:service-account-key/test-cutodian-scc@cloud-custodian.iam.gserviceaccount.com/2222",  # noqa: E501
            ],
        )

    def test_delete_service_account_key(self):
        factory = self.replay_flight_data("iam-delete-service-account-key")
        p = self.load_policy(
            {"name": "sa-key-delete", "resource": "gcp.service-account-key", "actions": ["delete"]},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        if self.recording:
            time.sleep(1)
        client = p.resource_manager.get_client()
        try:
            result = client.execute_query("get", {"name": resources[0]["name"]})
            self.fail("found deleted service account key: %s" % result)
        except HttpError as e:
            self.assertTrue("does not exist" in str(e))


class IAMRoleTest(BaseTest):
    def test_iam_role_query(self):
        project_id = "cloud-custodian"

        session_factory = self.replay_flight_data("ami-role-query", project_id)

        policy = self.load_policy(
            {"name": "ami-role-query", "resource": "gcp.iam-role"}, session_factory=session_factory
        )

        resources = policy.run()
        self.assertEqual(len(resources), 2)
        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [
                "gcp:iam:::role/accesscontextmanager.policyAdmin",
                "gcp:iam:::role/spanner.viewer",
            ],
        )

    def test_iam_role_get(self):
        project_id = "cloud-custodian"
        name = "accesscontextmanager.policyAdmin"

        session_factory = self.replay_flight_data("ami-role-query-get", project_id)

        policy = self.load_policy(
            {"name": "ami-role-query-get", "resource": "gcp.iam-role"},
            session_factory=session_factory,
        )

        resource = policy.resource_manager.get_resource(
            {
                "name": name,
            }
        )

        self.assertEqual(resource["name"], "roles/{}".format(name))
        self.assertEqual(
            policy.resource_manager.get_urns([resource]),
            [
                "gcp:iam:::role/accesscontextmanager.policyAdmin",
            ],
        )

    def test_iam_role_delete(self):
        project_id = "cloud-custodian"
        org_id = "111111111111"
        role_name = "customAccessContextManagerAdmin"
        full_role_name = f"organizations/{org_id}/roles/{role_name}"

        factory = self.replay_flight_data("iam-role-delete", project_id)

        p = self.load_policy(
            {
                "name": "role-delete",
                "resource": "gcp.iam-role",
                "filters": [{"name": full_role_name}],
                "actions": ["delete"],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        if self.recording:
            time.sleep(1)

        # Get client for organizations.roles to verify deletion
        from c7n.utils import local_session

        session = local_session(factory)
        client = session.client('iam', 'v1', 'organizations.roles')

        try:
            result = client.execute_query("get", {"name": full_role_name})
            # If role still exists, it should be marked as deleted
            self.assertTrue(result.get("deleted", False), "Role should be marked as deleted")
        except HttpError as e:
            # 404 is acceptable for deleted resources
            self.assertIn("404", str(e), f"Expected 404 for deleted role, got: {e}")

    def test_iam_role_delete_project_role(self):
        """Test deletion of project-scoped custom role"""
        project_id = "cloud-custodian"
        role_name = "customProjectRole"
        full_role_name = f"projects/{project_id}/roles/{role_name}"

        # Create mock resources
        resources = [{"name": full_role_name}]

        # Create policy
        p = self.load_policy(
            {
                "name": "role-delete-project",
                "resource": "gcp.iam-role",
                "actions": ["delete"],
            }
        )

        # Mock the session and clients
        mock_session = mock.MagicMock()
        mock_session.get_default_project.return_value = project_id

        mock_projects_client = mock.MagicMock()
        mock_projects_client.execute_command = mock.MagicMock(return_value={})

        def mock_client_factory(service, version, component):
            if component == 'projects.roles':
                return mock_projects_client
            return mock.MagicMock()

        mock_session.client = mock_client_factory

        # Execute the action
        action = p.resource_manager.actions[0]
        action.manager.session_factory = lambda: mock_session

        with mock.patch('c7n_gcp.resources.iam.local_session', return_value=mock_session):
            # This should not raise an exception
            action.process(resources)

        # Verify the correct client was used and delete was called
        mock_projects_client.execute_command.assert_called_once_with(
            'delete', {'name': full_role_name}
        )

    def test_iam_role_delete_predefined_role(self):
        """Test that predefined roles are skipped (not deleted)"""
        project_id = "cloud-custodian"
        predefined_role = "roles/viewer"

        # Create mock resources with a predefined role
        resources = [{"name": predefined_role}]

        # Create policy
        p = self.load_policy(
            {
                "name": "role-delete-predefined",
                "resource": "gcp.iam-role",
                "actions": ["delete"],
            }
        )

        # Mock the session
        mock_session = mock.MagicMock()
        mock_session.get_default_project.return_value = project_id
        mock_client = mock.MagicMock()
        mock_session.client = mock.MagicMock(return_value=mock_client)

        # Execute the action
        action = p.resource_manager.actions[0]
        action.manager.session_factory = lambda: mock_session

        with mock.patch('c7n_gcp.resources.iam.local_session', return_value=mock_session):
            # This should not raise an exception, just log and skip
            action.process(resources)

        # Verify that no delete was attempted (client.execute_command not called)
        mock_client.execute_command.assert_not_called()

    def test_iam_role_delete_invalid_org_role_format(self):
        """Test handling of malformed organizational role names"""
        project_id = "cloud-custodian"
        # Invalid format: missing 'roles' segment
        invalid_role = "organizations/123456/invalid/customRole"

        resources = [{"name": invalid_role}]

        p = self.load_policy(
            {
                "name": "role-delete-invalid",
                "resource": "gcp.iam-role",
                "actions": ["delete"],
            }
        )

        mock_session = mock.MagicMock()
        mock_session.get_default_project.return_value = project_id
        mock_org_client = mock.MagicMock()
        mock_org_client.execute_command = mock.MagicMock(return_value={})
        mock_session.client = mock.MagicMock(return_value=mock_org_client)

        action = p.resource_manager.actions[0]
        action.manager.session_factory = lambda: mock_session

        with mock.patch('c7n_gcp.resources.iam.local_session', return_value=mock_session):
            # Should not raise exception - logs error but continues with delete attempt
            # (current behavior - role_name will be None but delete is still attempted)
            action.process(resources)

        # Verify delete was attempted despite invalid format (current behavior)
        mock_org_client.execute_command.assert_called_once_with('delete', {'name': invalid_role})

    def test_iam_role_delete_invalid_project_role_format(self):
        """Test handling of malformed project role names"""
        project_id = "cloud-custodian"
        # Invalid format: missing 'roles' segment
        invalid_role = "projects/my-project/wrongpath/customRole"

        resources = [{"name": invalid_role}]

        p = self.load_policy(
            {
                "name": "role-delete-invalid-project",
                "resource": "gcp.iam-role",
                "actions": ["delete"],
            }
        )

        mock_session = mock.MagicMock()
        mock_session.get_default_project.return_value = project_id
        mock_project_client = mock.MagicMock()
        mock_project_client.execute_command = mock.MagicMock(return_value={})
        mock_session.client = mock.MagicMock(return_value=mock_project_client)

        action = p.resource_manager.actions[0]
        action.manager.session_factory = lambda: mock_session

        with mock.patch('c7n_gcp.resources.iam.local_session', return_value=mock_session):
            # Should not raise exception - logs error but continues with delete attempt
            # (current behavior - role_name will be None but delete is still attempted)
            action.process(resources)

        # Verify delete was attempted despite invalid format (current behavior)
        mock_project_client.execute_command.assert_called_once_with(
            'delete', {'name': invalid_role}
        )

    def test_iam_role_delete_http_error(self):
        """Test that HttpError during deletion is handled"""
        project_id = "cloud-custodian"
        org_id = "111111111111"
        role_name = "customRole"
        full_role_name = f"organizations/{org_id}/roles/{role_name}"

        resources = [{"name": full_role_name}]

        p = self.load_policy(
            {
                "name": "role-delete-error",
                "resource": "gcp.iam-role",
                "actions": ["delete"],
            }
        )

        mock_session = mock.MagicMock()
        mock_session.get_default_project.return_value = project_id
        mock_org_client = mock.MagicMock()

        # Simulate HttpError during deletion
        from googleapiclient.errors import HttpError
        from unittest.mock import MagicMock

        # Create a proper HttpError
        resp = MagicMock()
        resp.status = 403
        resp.reason = "Permission denied"
        http_error = HttpError(resp=resp, content=b'{"error": {"message": "Permission denied"}}')

        mock_org_client.execute_command.side_effect = http_error
        mock_session.client = mock.MagicMock(return_value=mock_org_client)

        action = p.resource_manager.actions[0]
        action.manager.session_factory = lambda: mock_session

        with mock.patch('c7n_gcp.resources.iam.local_session', return_value=mock_session):
            # Should not raise exception - handle_resource_error is called
            action.process(resources)

        # Verify delete was attempted
        mock_org_client.execute_command.assert_called_once_with('delete', {'name': full_role_name})


class ApiKeyTest(BaseTest):
    def test_api_key_query(self):
        project_id = "cloud-custodian"
        factory = self.replay_flight_data("api-key-list", project_id)
        p = self.load_policy(
            {
                "name": "gcp-api-key-list",
                "resource": "gcp.api-key",
                "filters": [{"name": "projects/cloud-custodian/locations/global/keys/xxxx-xxxx"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_api_key_time_range(self):
        project_id = "cloud-custodian"
        factory = self.replay_flight_data("gcp-apikeys-time-range", project_id)
        p = self.load_policy(
            {
                "name": "gcp-api-key-list",
                "resource": "gcp.api-key",
                "filters": [{"type": "time-range", "value": 30}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(
            resources[0]["name"],
            "projects/cloud-custodian/locations/global/keys/03b651c2-718a-4702-b5d7-9946987cc4da",
        )
