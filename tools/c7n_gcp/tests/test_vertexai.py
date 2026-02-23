# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from pytest_terraform import terraform
import time


def test_vertexai_endpoint_multi_location(test):
    """Test querying Vertex AI Endpoints across multiple locations.

    This test verifies that we can query endpoints in multiple locations
    in a single policy run by specifying multiple locations in the query.
    """
    session_factory = test.replay_flight_data('vertexai-endpoint-multi-location')

    # Query both us-central1 and us-east1 in a single policy
    policy = test.load_policy(
        {'name': 'vertexai-endpoints-multi-location',
         'resource': 'gcp.vertex-ai-endpoint',
         'query': [
             {'location': 'us-central1'},
             {'location': 'us-east1'}
         ]},
        session_factory=session_factory)

    resources = policy.run()

    # Should find endpoints from both locations
    assert len(resources) >= 2

    # Verify we have resources from both locations
    locations = {r['name'].split('/')[3] for r in resources}
    assert 'us-central1' in locations
    assert 'us-east1' in locations

    # Verify each resource has the c7n:location annotation
    assert all('c7n:location' in r for r in resources)


def test_vertexai_endpoint_filtering(test,):
    """Test filtering Vertex AI Endpoints on common fields.

    This test explicitly verifies that value filters work correctly on
    endpoint displayName field.
    """
    session_factory = test.replay_flight_data('vertexai-endpoint-filtering')

    # Filter by displayName using regex
    policy = test.load_policy(
        {'name': 'filter-by-display-name',
         'resource': 'gcp.vertex-ai-endpoint',
         'query': [
             {'location': 'us-central1'},
             {'location': 'us-east1'}
         ],
         'filters': [
             {'type': 'value',
              'key': 'displayName',
              'op': 'regex',
              'value': '.*-central$'}
         ]},
        session_factory=session_factory)

    resources = policy.run()

    # Should only find endpoints with names ending in '-central'
    assert len(resources) >= 1
    assert all(r['displayName'].endswith('-central') for r in resources)


def test_vertexai_endpoint_delete(test):
    """Test deleting Vertex AI Endpoints.

    This test verifies that the delete action can successfully delete
    endpoints across multiple locations.
    """
    session_factory = test.replay_flight_data('vertexai-endpoint-delete')

    policy = test.load_policy(
        {'name': 'delete-test-endpoints',
         'resource': 'gcp.vertex-ai-endpoint',
         'query': [
             {'location': 'us-central1'}
         ],
         'filters': [
             {'type': 'value',
              'key': 'displayName',
              'op': 'regex',
              'value': 'c7n-.*'}
         ],
         'actions': [
             {'type': 'delete'}
         ]},
        session_factory=session_factory)

    resources = policy.run()

    # Verify that resources were found and deleted
    assert len(resources) >= 1

    # Verify all resources have the expected naming pattern
    assert all('c7n-' in r.get('displayName', '') for r in resources)

    # Re-query to verify the endpoint was actually deleted
    if test.recording:
        time.sleep(1)

    verify_policy = test.load_policy(
        {'name': 'verify-deletion',
         'resource': 'gcp.vertex-ai-endpoint',
         'query': [
             {'location': 'us-central1'}
         ],
         'filters': [
             {'type': 'value',
              'key': 'displayName',
              'op': 'regex',
              'value': 'c7n-.*'}
         ]},
        session_factory=session_factory)

    remaining_resources = verify_policy.run()

    # Verify that the endpoint no longer exists
    assert len(remaining_resources) == 0
