# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import os
import json
import time
from google.api_core.client_options import ClientOptions

from pytest_terraform import terraform


def get_test_model_id(project_id, location):
    """Get full model resource name for testing.

    Uses the model ID from environment variable and constructs the full
    resource path for the specified location.

    Args:
        project_id: GCP project ID
        location: GCP location (e.g., 'us-central1')

    Returns:
        Full model resource path

    Raises:
        RuntimeError: If the required environment variable is not set
    """
    ENV_VARS = {
        'us-central1': 'GCP_VERTEX_AI_TEST_MODEL_ID_CENTRAL',
        'us-east1': 'GCP_VERTEX_AI_TEST_MODEL_ID_EAST'
    }

    env_var = ENV_VARS[location]
    if env_var not in os.environ:
        raise RuntimeError(
            f'Environment variable {env_var} is required for testing.\n'
            f'Set it to a valid model ID:\n'
            f'  export {env_var}="<ID>"'
        )

    model_id = os.environ[env_var]
    full_path = f'projects/{project_id}/locations/{location}/models/{model_id}'
    print(f'Using model: {full_path} ({location})')
    return full_path


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


def test_vertexai_batch_prediction_job_multi_location(test):
    """Test querying Vertex AI Batch Prediction Jobs across multiple locations.

    This test verifies that we can query batch prediction jobs in multiple locations
    in a single policy run by specifying multiple locations in the query.
    """
    session_factory = test.replay_flight_data(
        'vertexai-batch-prediction-job-multi-location')

    # When recording, create batch prediction jobs via API
    if test.recording:
        session = session_factory()
        project_id = session.get_default_project()

        # Get terraform outputs from tf_resources.json
        tf_dir = os.path.join(
            os.path.dirname(__file__),
            'terraform/vertexai_batch_prediction_job'
        )
        tf_resources_file = os.path.join(tf_dir, 'tf_resources.json')

        with open(tf_resources_file, 'r') as f:
            tf_data = json.load(f)

        # Extract outputs
        outputs = tf_data['outputs']
        input_uri_us_central1 = outputs['input_uri_us_central1']['value']
        input_uri_us_east1 = outputs['input_uri_us_east1']['value']
        output_uri_us_central1 = outputs['output_uri_us_central1']['value']
        output_uri_us_east1 = outputs['output_uri_us_east1']['value']

        # Create batch prediction job in us-central1
        client_options_central = ClientOptions(
            api_endpoint='https://us-central1-aiplatform.googleapis.com'
        )
        client_central = session.client(
            'aiplatform', 'v1',
            'projects.locations.batchPredictionJobs',
            client_options=client_options_central
        )

        model_id_central = get_test_model_id(project_id, 'us-central1')

        job_config_central = {
            'displayName': 'c7n-test-batch-job-central',
            'model': model_id_central,
            'inputConfig': {
                'instancesFormat': 'jsonl',
                'gcsSource': {
                    'uris': [input_uri_us_central1]
                }
            },
            'outputConfig': {
                'predictionsFormat': 'jsonl',
                'gcsDestination': {
                    'outputUriPrefix': output_uri_us_central1
                }
            },
            'dedicatedResources': {
                'machineSpec': {
                    'machineType': 'n1-standard-2'
                },
                'startingReplicaCount': 1
            }
        }

        client_central.execute_command(
            'create',
            {
                'parent': f'projects/{project_id}/locations/us-central1',
                'body': job_config_central
            }
        )

        # Create batch prediction job in us-east1
        client_options_east = ClientOptions(
            api_endpoint='https://us-east1-aiplatform.googleapis.com'
        )
        client_east = session.client(
            'aiplatform', 'v1',
            'projects.locations.batchPredictionJobs',
            client_options=client_options_east
        )

        model_id_east = get_test_model_id(project_id, 'us-east1')

        job_config_east = {
            'displayName': 'c7n-test-batch-job-east',
            'model': model_id_east,
            'inputConfig': {
                'instancesFormat': 'jsonl',
                'gcsSource': {
                    'uris': [input_uri_us_east1]
                }
            },
            'outputConfig': {
                'predictionsFormat': 'jsonl',
                'gcsDestination': {
                    'outputUriPrefix': output_uri_us_east1
                }
            },
            'dedicatedResources': {
                'machineSpec': {
                    'machineType': 'n1-standard-2'
                },
                'startingReplicaCount': 1
            }
        }

        client_east.execute_command(
            'create',
            {
                'parent': f'projects/{project_id}/locations/us-east1',
                'body': job_config_east
            }
        )

    # Query both us-central1 and us-east1 in a single policy
    policy = test.load_policy(
        {'name': 'vertexai-batch-jobs-multi-location',
         'resource': 'gcp.vertex-ai-batch-prediction-job',
         'query': [
             {'location': 'us-central1'},
             {'location': 'us-east1'}
         ]},
        session_factory=session_factory)

    resources = policy.run()

    # Should find batch jobs from both locations
    assert len(resources) >= 2

    # Verify we have resources from both locations
    locations = {r['name'].split('/')[3] for r in resources}
    assert 'us-central1' in locations
    assert 'us-east1' in locations


# @terraform('vertexai_batch_prediction_job')
# def test_vertexai_batch_prediction_job_filtering(test, vertexai_batch_prediction_job):
#     """Test filtering Vertex AI Batch Prediction Jobs on state and other fields.

#     This test verifies that value filters work correctly on batch job fields.

#     Note: This test relies on jobs created by the multi_location test.
#     Run that test first when recording.
#     """
#     session_factory = test.replay_flight_data(
#         'vertexai-batch-prediction-job-filtering')

#     # Filter by state
#     policy = test.load_policy(
#         {'name': 'filter-by-state',
#          'resource': 'gcp.vertex-ai-batch-prediction-job',
#          'query': [
#              {'location': 'us-central1'},
#              {'location': 'us-east1'}
#          ],
#          'filters': [
#              {'type': 'value',
#               'key': 'state',
#               'value': 'JOB_STATE_SUCCEEDED'}
#          ]},
#         session_factory=session_factory)

#     resources = policy.run()

#     # Should only find succeeded jobs (if any exist)
#     # Note: Jobs may still be running when test executes
#     if len(resources) > 0:
#         assert all(r['state'] == 'JOB_STATE_SUCCEEDED' for r in resources)


# @terraform('vertexai_batch_prediction_job')
# def test_vertexai_batch_prediction_job_delete(test, vertexai_batch_prediction_job):
#     """Test deleting Vertex AI Batch Prediction Jobs.

#     This test verifies that the delete action can successfully delete
#     batch prediction jobs across multiple locations.
#     """
#     session_factory = test.replay_flight_data(
#         'vertexai-batch-prediction-job-delete')

#     # When recording, create a batch prediction job to delete
#     if test.recording:
#         session = session_factory()
#         project_id = session.get_default_project()
#         tf_outputs = vertexai_batch_prediction_job
#         input_uri = tf_outputs.outputs['input_uri_us_central1']['value']
#         output_uri = tf_outputs.outputs['output_uri_us_central1']['value']

#         model_id = get_test_model_id()

#         client = session.client(
#             'aiplatform', 'v1',
#             'projects.locations.batchPredictionJobs',
#             regional_endpoint='us-central1-aiplatform.googleapis.com'
#         )

#         job_config = {
#             'displayName': 'c7n-test-delete-job',
#             'model': model_id,
#             'inputConfig': {
#                 'instancesFormat': 'jsonl',
#                 'gcsSource': {'uris': [input_uri]}
#             },
#             'outputConfig': {
#                 'predictionsFormat': 'jsonl',
#                 'gcsDestination': {'outputUriPrefix': output_uri}
#             }
#         }

#         client.execute_command(
#             'create',
#             {
#                 'parent': f'projects/{project_id}/locations/us-central1',
#                 'body': job_config
#             }
#         )
#         time.sleep(5)

#     policy = test.load_policy(
#         {'name': 'delete-test-batch-jobs',
#          'resource': 'gcp.vertex-ai-batch-prediction-job',
#          'query': [
#              {'location': 'us-central1'}
#          ],
#          'filters': [
#              {'type': 'value',
#               'key': 'displayName',
#               'op': 'regex',
#               'value': 'c7n-.*'}
#          ],
#          'actions': [
#              {'type': 'delete'}
#          ]},
#         session_factory=session_factory)

#     resources = policy.run()

#     # Verify that resources were found and deleted
#     assert len(resources) >= 1

#     # Verify all resources have the expected naming pattern
#     assert all('c7n-' in r.get('displayName', '') for r in resources)

#     # Re-query to verify the job was actually deleted
#     if test.recording:
#         time.sleep(1)

#     verify_policy = test.load_policy(
#         {'name': 'verify-deletion',
#          'resource': 'gcp.vertex-ai-batch-prediction-job',
#          'query': [
#              {'location': 'us-central1'}
#          ],
#          'filters': [
#              {'type': 'value',
#               'key': 'displayName',
#               'op': 'regex',
#               'value': 'c7n-.*'}
#          ]},
#         session_factory=session_factory)

#     remaining_resources = verify_policy.run()

#     # Verify that the job no longer exists
#     assert len(remaining_resources) == 0


# @terraform('vertexai_batch_prediction_job')
# def test_vertexai_batch_prediction_job_stop(test, vertexai_batch_prediction_job):
#     """Test stopping (cancelling) Vertex AI Batch Prediction Jobs.

#     This test verifies that the stop action can successfully cancel
#     running batch prediction jobs.
#     """
#     session_factory = test.replay_flight_data(
#         'vertexai-batch-prediction-job-stop')

#     # When recording, create a batch prediction job to stop
#     if test.recording:
#         session = session_factory()
#         project_id = session.get_default_project()
#         tf_outputs = vertexai_batch_prediction_job
#         input_uri = tf_outputs.outputs['input_uri_us_central1']['value']
#         output_uri = tf_outputs.outputs['output_uri_us_central1']['value']

#         model_id = get_test_model_id()

#         client = session.client(
#             'aiplatform', 'v1',
#             'projects.locations.batchPredictionJobs',
#             regional_endpoint='us-central1-aiplatform.googleapis.com'
#         )

#         job_config = {
#             'displayName': 'c7n-test-stop-job',
#             'model': model_id,
#             'inputConfig': {
#                 'instancesFormat': 'jsonl',
#                 'gcsSource': {'uris': [input_uri]}
#             },
#             'outputConfig': {
#                 'predictionsFormat': 'jsonl',
#                 'gcsDestination': {'outputUriPrefix': output_uri}
#             }
#         }

#         client.execute_command(
#             'create',
#             {
#                 'parent': f'projects/{project_id}/locations/us-central1',
#                 'body': job_config
#             }
#         )
#         # Wait a bit for job to start running
#         time.sleep(5)

#     policy = test.load_policy(
#         {'name': 'stop-running-batch-jobs',
#          'resource': 'gcp.vertex-ai-batch-prediction-job',
#          'query': [
#              {'location': 'us-central1'}
#          ],
#          'filters': [
#              {'type': 'value',
#               'key': 'state',
#               'value': 'JOB_STATE_RUNNING'},
#              {'type': 'value',
#               'key': 'displayName',
#               'op': 'regex',
#               'value': 'c7n-.*'}
#          ],
#          'actions': [
#              {'type': 'stop'}
#          ]},
#         session_factory=session_factory)

#     resources = policy.run()

#     # Verify that resources were found and stopped
#     assert len(resources) >= 1

#     # Verify all resources were in running state
#     assert all(r['state'] == 'JOB_STATE_RUNNING' for r in resources)

#     # Re-query to verify the job was cancelled
#     if test.recording:
#         time.sleep(2)

#     verify_policy = test.load_policy(
#         {'name': 'verify-cancellation',
#          'resource': 'gcp.vertex-ai-batch-prediction-job',
#          'query': [
#              {'location': 'us-central1'}
#          ],
#          'filters': [
#              {'type': 'value',
#               'key': 'displayName',
#               'op': 'regex',
#               'value': 'c7n-.*'}
#          ]},
#         session_factory=session_factory)

#     updated_resources = verify_policy.run()

#     # Verify that the job state changed (should be CANCELLED or CANCELLING)
#     if len(updated_resources) > 0:
#         assert all(
#             r['state'] in ['JOB_STATE_CANCELLED', 'JOB_STATE_CANCELLING']
#             for r in updated_resources
#         )
