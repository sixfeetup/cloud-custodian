# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from gcp_common import BaseTest
from c7n_gcp.client import get_default_project
from c7n.testing import C7N_FUNCTIONAL


class VertexAIPublisherModelTest(BaseTest):
    """Test Vertex AI Publisher Models resource

    Tests the gcp.vertex-ai-publisher-model resource which provides access
    to the Vertex AI Model Garden catalog of publisher models.

    Note: This resource queries a read-only catalog provided by Google,
    so no terraform infrastructure is needed.

    API Version: Uses v1beta1 because v1 does not support list operations.
    If tests start failing, check if the v1beta1 API has been deprecated
    or if v1 has gained list support (see vertexai.py VertexAIPublisherModel for migration path).
    """

    def test_publisher_model_query(self):
        """Test listing Vertex AI publisher models."""

        # Use record_flight_data in functional mode, replay_flight_data otherwise
        if C7N_FUNCTIONAL:  # pragma: no cover
            project_id = get_default_project()
            session_factory = self.record_flight_data(
                'vertex-ai-publisher-model-query', project_id=project_id)
        else:
            session_factory = self.replay_flight_data('vertex-ai-publisher-model-query')

        policy = self.load_policy(
            {'name': 'vertex-ai-publisher-models',
             'resource': 'gcp.vertex-ai-publisher-model'},
            session_factory=session_factory)

        resources = policy.run()

        # Basic assertions
        self.assertIsNotNone(resources)
        if len(resources) > 0:
            self.assertIn('name', resources[0])

    def test_publisher_model_filter_by_launch_stage(self):
        """Test filtering publisher models by launch stage."""
        if C7N_FUNCTIONAL:  # pragma: no cover
            project_id = get_default_project()
            session_factory = self.record_flight_data(
                'vertex-ai-publisher-model-filter-launch-stage', project_id=project_id)
        else:
            session_factory = self.replay_flight_data(
                'vertex-ai-publisher-model-filter-launch-stage')

        policy = self.load_policy(
            {'name': 'ga-publisher-models',
             'resource': 'gcp.vertex-ai-publisher-model',
             'filters': [
                 {'type': 'value',
                  'key': 'launchStage',
                  'value': 'GA'}
             ]},
            session_factory=session_factory)

        resources = policy.run()

        print(f'\n=== Found {len(resources)} GA models ===')
        if resources:
            print(f'First GA model: {resources[0].get("name")}')

        # Verify all returned models are GA
        self.assertIsNotNone(resources)
        for resource in resources:
            self.assertEqual(resource.get('launchStage'), 'GA',
                           f'Model {resource.get("name")} is not GA')

    def test_publisher_model_filter_by_name_pattern(self):
        """Test filtering publisher models by name pattern."""
        if C7N_FUNCTIONAL:  # pragma: no cover
            project_id = get_default_project()
            session_factory = self.record_flight_data(
                'vertex-ai-publisher-model-filter-name', project_id=project_id)
        else:
            session_factory = self.replay_flight_data(
                'vertex-ai-publisher-model-filter-name')

        policy = self.load_policy(
            {'name': 'gemini-models',
             'resource': 'gcp.vertex-ai-publisher-model',
             'filters': [
                 {'type': 'value',
                  'key': 'name',
                  'op': 'regex',
                  'value': '.*gemini.*'}
             ]},
            session_factory=session_factory)

        resources = policy.run()

        print(f'\n=== Found {len(resources)} Gemini models ===')
        if resources:
            for r in resources[:3]:
                print(f'  - {r.get("name")}')

        # Verify all returned models have 'gemini' in the name
        self.assertIsNotNone(resources)
        for resource in resources:
            self.assertIn('gemini', resource.get('name', '').lower(),
                        f'Model {resource.get("name")} does not match pattern')

    def test_publisher_model_field_validation(self):
        """Test that expected fields are present in publisher model resources."""
        if C7N_FUNCTIONAL:  # pragma: no cover
            project_id = get_default_project()
            session_factory = self.record_flight_data(
                'vertex-ai-publisher-model-fields', project_id=project_id)
        else:
            session_factory = self.replay_flight_data(
                'vertex-ai-publisher-model-fields')

        policy = self.load_policy(
            {'name': 'validate-fields',
             'resource': 'gcp.vertex-ai-publisher-model'},
            session_factory=session_factory)

        resources = policy.run()

        self.assertGreater(len(resources), 0, 'Should return at least one model')

        # Validate expected fields are present
        expected_fields = ['name', 'versionId', 'launchStage', 'publisherModelTemplate']
        model = resources[0]

        print(f'\n=== Field Validation for {model.get("name")} ===')
        for field in expected_fields:
            self.assertIn(field, model, f'Missing expected field: {field}')
            print(f'  ✓ {field}: {model.get(field)}')

        # Validate field types
        self.assertIsInstance(model.get('name'), str)
        self.assertIsInstance(model.get('versionId'), str)
        self.assertIsInstance(model.get('launchStage'), str)

    def test_publisher_model_multiple_filters(self):
        """Test combining multiple filters on publisher models."""
        if C7N_FUNCTIONAL:  # pragma: no cover
            project_id = get_default_project()
            session_factory = self.record_flight_data(
                'vertex-ai-publisher-model-multi-filter', project_id=project_id)
        else:
            session_factory = self.replay_flight_data(
                'vertex-ai-publisher-model-multi-filter')

        policy = self.load_policy(
            {'name': 'ga-gemini-models',
             'resource': 'gcp.vertex-ai-publisher-model',
             'filters': [
                 {'type': 'value',
                  'key': 'launchStage',
                  'value': 'GA'},
                 {'type': 'value',
                  'key': 'name',
                  'op': 'regex',
                  'value': '.*gemini.*'}
             ]},
            session_factory=session_factory)

        resources = policy.run()

        print(f'\n=== Found {len(resources)} GA Gemini models ===')

        # Verify all returned models match both filters
        self.assertIsNotNone(resources)
        for resource in resources:
            self.assertEqual(resource.get('launchStage'), 'GA')
            self.assertIn('gemini', resource.get('name', '').lower())
            print(f'  - {resource.get("name")} (v{resource.get("versionId")})')

    def test_publisher_model_non_google_publisher(self):
        """Test filtering for non-Gemini publisher models.

        Note: This test filters the Google publisher results for non-Gemini models.
        The resource currently queries publishers/google, which may include models
        from various publishers in the Google catalog.
        """
        if C7N_FUNCTIONAL:  # pragma: no cover
            project_id = get_default_project()
            session_factory = self.record_flight_data(
                'vertex-ai-publisher-model-non-google', project_id=project_id)
        else:
            session_factory = self.replay_flight_data(
                'vertex-ai-publisher-model-non-google')

        policy = self.load_policy(
            {'name': 'non-gemini-models',
             'resource': 'gcp.vertex-ai-publisher-model',
             'filters': [
                 {'not': [
                     {'type': 'value',
                      'key': 'name',
                      'op': 'regex',
                      'value': '.*gemini.*'}
                 ]}
             ]},
            session_factory=session_factory)

        resources = policy.run()

        print(f'\n=== Found {len(resources)} non-Gemini models ===')
        if resources:
            for r in resources[:5]:
                print(f'  - {r.get("name")}')
