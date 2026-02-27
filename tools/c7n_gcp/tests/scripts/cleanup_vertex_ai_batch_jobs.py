#!/usr/bin/env python3
"""
Script to delete old Vertex AI Batch Prediction Jobs.
This helps clean up test jobs that may interfere with functional tests.

Usage:
    python cleanup_batch_jobs.py [--project PROJECT_ID] [--pattern PATTERN]
"""

import argparse
import time
from google.api_core.client_options import ClientOptions
from googleapiclient import discovery
from google.auth import default

# Configuration
LOCATIONS = ['us-central1', 'us-east1']
DEFAULT_PATTERN = 'c7n-test'


def get_credentials_and_project(project_id=None):
    """Get credentials and project ID."""
    credentials, default_project = default()
    project = project_id or default_project
    return credentials, project


def list_batch_jobs(credentials, project_id, location):
    """List all batch prediction jobs in a location."""
    client_options = ClientOptions(
        api_endpoint=f'https://{location}-aiplatform.googleapis.com'
    )

    service = discovery.build(
        'aiplatform', 'v1',
        credentials=credentials,
        client_options=client_options
    )

    parent = f'projects/{project_id}/locations/{location}'

    try:
        request = service.projects().locations().batchPredictionJobs().list(
            parent=parent
        )
        response = request.execute()
        return response.get('batchPredictionJobs', [])
    except Exception as e:
        print(f'  Error listing jobs: {e}')
        return []


def cancel_job(credentials, job_name, location):
    """Cancel a running batch prediction job."""
    client_options = ClientOptions(
        api_endpoint=f'https://{location}-aiplatform.googleapis.com'
    )

    service = discovery.build(
        'aiplatform', 'v1',
        credentials=credentials,
        client_options=client_options
    )

    try:
        request = service.projects().locations().batchPredictionJobs().cancel(
            name=job_name
        )
        request.execute()
        return True
    except Exception as e:
        print(f'    Failed to cancel: {e}')
        return False


def delete_job(credentials, job_name, location):
    """Delete a batch prediction job."""
    client_options = ClientOptions(
        api_endpoint=f'https://{location}-aiplatform.googleapis.com'
    )

    service = discovery.build(
        'aiplatform', 'v1',
        credentials=credentials,
        client_options=client_options
    )

    try:
        request = service.projects().locations().batchPredictionJobs().delete(
            name=job_name
        )
        request.execute()
        return True
    except Exception as e:
        print(f'    Failed to delete: {e}')
        return False


def cleanup_location(credentials, project_id, location, pattern):
    """Clean up jobs in a specific location."""
    print(f'Processing location: {location}')

    jobs = list_batch_jobs(credentials, project_id, location)

    if not jobs:
        print('  No jobs found')
        return

    deleted_count = 0

    for job in jobs:
        display_name = job.get('displayName', '')
        job_name = job.get('name', '')
        state = job.get('state', '')

        # Check if display name matches our test pattern
        if pattern in display_name:
            print(f'  Found test job: {display_name} (state: {state})')

            # Cancel job if it's running or pending
            if state in ['JOB_STATE_RUNNING', 'JOB_STATE_PENDING', 'JOB_STATE_CANCELLING']:
                print('    Cancelling job...')
                cancel_job(credentials, job_name, location)
                # Wait for cancellation to complete
                time.sleep(10)

            # Delete the job
            print('    Deleting job...')
            if delete_job(credentials, job_name, location):
                deleted_count += 1
                print('    ✓ Deleted')
            else:
                print('    ✗ Failed to delete')

    print(f'  Deleted {deleted_count} job(s) in {location}')


def main():
    parser = argparse.ArgumentParser(
        description='Clean up Vertex AI Batch Prediction Jobs'
    )
    parser.add_argument(
        '--project',
        help='GCP Project ID (default: from gcloud config)'
    )
    parser.add_argument(
        '--pattern',
        default=DEFAULT_PATTERN,
        help=f'Display name pattern to match (default: {DEFAULT_PATTERN})'
    )

    args = parser.parse_args()

    credentials, project_id = get_credentials_and_project(args.project)

    print('=== Cleaning up Vertex AI Batch Prediction Jobs ===')
    print(f'Project: {project_id}')
    print(f'Locations: {LOCATIONS}')
    print(f'Display name pattern: {args.pattern}')
    print('')

    for location in LOCATIONS:
        cleanup_location(credentials, project_id, location, args.pattern)
        print('')

    print('=== Cleanup complete ===')


if __name__ == '__main__':
    main()
