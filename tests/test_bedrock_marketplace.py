# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import os
import time

import pytest
from botocore.exceptions import ClientError
from pytest_terraform import terraform

REGION = "us-east-1"

# Free (no EULA), using the smallest confirmed instance type
# (ml.g5.xlarge) among surveyed models -- see
# tests/terraform/bedrock_marketplace_model_endpoint/list_free_models.py,
# which prints default_instance/supported_instances per model. Overridable
# at test time -- e.g. a re-recording that picks a different model as this
# catalog's models are added/removed -- via MARKETPLACE_MODEL_SOURCE_IDENTIFIER.
# See tests/terraform/bedrock_marketplace_model_endpoint/README.md.
DEFAULT_MARKETPLACE_MODEL_SOURCE_IDENTIFIER = (
    "arn:aws:sagemaker:us-east-1:aws:hub-content/SageMakerPublicHub/Model/"
    "huggingface-llm-mistral-7b-openorca-gptq/1.3.17"
)
MARKETPLACE_MODEL_SOURCE_IDENTIFIER = os.environ.get(
    "MARKETPLACE_MODEL_SOURCE_IDENTIFIER", DEFAULT_MARKETPLACE_MODEL_SOURCE_IDENTIFIER)
MARKETPLACE_ENDPOINT_INSTANCE_TYPE = os.environ.get(
    "MARKETPLACE_ENDPOINT_INSTANCE_TYPE", "ml.g5.xlarge")

WAITER_DELAY_SECONDS = 15
IAM_PROPAGATION_TIMEOUT_SECONDS = 300
# SageMaker endpoint creation can take well over the ~12-15 minutes AWS
# documents as typical -- capacity-constrained instance types (e.g.
# InsufficientInstanceCapacity) have taken up to 45 minutes to resolve.
ENDPOINT_ACTIVE_TIMEOUT_SECONDS = 3600
ENDPOINT_POLL_INTERVAL_SECONDS = 20


def is_iam_propagation_error(err: ClientError) -> bool:
    code = err.response.get("Error", {}).get("Code", "")
    message = err.response.get("Error", {}).get("Message", "").lower()
    if code not in {"ValidationException", "AccessDeniedException"}:
        return False
    return any(
        token in message
        for token in ("cannot be assumed", "unable to assume", "not authorized", "role")
    )


def wait_for_marketplace_endpoint_active(client, endpoint_arn, test):
    start = time.monotonic()
    deadline = start + ENDPOINT_ACTIVE_TIMEOUT_SECONDS
    endpoint = None
    while time.monotonic() < deadline:
        endpoint = client.get_marketplace_model_endpoint(
            endpointArn=endpoint_arn)['marketplaceModelEndpoint']
        if endpoint['status'] == 'REGISTERED' and endpoint['endpointStatus'] == 'InService':
            return endpoint
        if endpoint['endpointStatus'] == 'Failed':
            raise RuntimeError(
                f"marketplace model endpoint {endpoint_arn} failed: "
                f"{endpoint['endpointStatusMessage']}")
        if test.recording:
            elapsed = int(time.monotonic() - start)
            print(
                f"[{elapsed}s] waiting for {endpoint_arn} to become active "
                f"(status={endpoint['status']}, "
                f"endpointStatus={endpoint['endpointStatus']})")
            time.sleep(ENDPOINT_POLL_INTERVAL_SECONDS)
    raise RuntimeError(
        f"marketplace model endpoint {endpoint_arn} did not become active: {endpoint}")


@pytest.fixture
def create_marketplace_model_endpoint(test):
    """Create a Bedrock Marketplace model endpoint, and delete it after.

    Not a Terraform fixture: the AWS provider has no resource for it
    (hashicorp/terraform-provider-aws#41370). Set ``test.session_factory``
    first, so its calls record with the test. This provisions a real,
    dedicated SageMaker instance billed per instance-hour -- see
    tests/terraform/bedrock_marketplace_model_endpoint/README.md.
    """
    created = []

    def _create(execution_role_arn, name="c7n-mp-endpoint-test"):  # <= 30 chars, AWS limit
        client = test.session_factory().client('bedrock', region_name=REGION)
        request = dict(
            modelSourceIdentifier=MARKETPLACE_MODEL_SOURCE_IDENTIFIER,
            endpointName=name,
            acceptEula=True,
            endpointConfig={
                'sageMaker': {
                    'initialInstanceCount': 1,
                    'instanceType': MARKETPLACE_ENDPOINT_INSTANCE_TYPE,
                    'executionRole': execution_role_arn,
                }
            },
        )

        # The execution role is freshly created by the Terraform fixture and
        # can take a few seconds to propagate through IAM, so a newly created
        # SageMaker endpoint intermittently fails to assume it at first.
        deadline = time.monotonic() + IAM_PROPAGATION_TIMEOUT_SECONDS
        while True:
            try:
                response = client.create_marketplace_model_endpoint(**request)
                break
            except ClientError as err:
                if not test.recording or not is_iam_propagation_error(err) \
                        or time.monotonic() >= deadline:
                    raise
                time.sleep(WAITER_DELAY_SECONDS)

        endpoint_arn = response['marketplaceModelEndpoint']['endpointArn']
        created.append((client, endpoint_arn))
        wait_for_marketplace_endpoint_active(client, endpoint_arn, test)
        return endpoint_arn

    try:
        yield _create
    finally:
        for client, endpoint_arn in created:
            try:
                client.delete_marketplace_model_endpoint(endpointArn=endpoint_arn)
            except client.exceptions.ResourceNotFoundException:
                pass


def emit_invocation(session_factory, endpoint_arn):
    runtime = session_factory().client('bedrock-runtime', region_name=REGION)
    runtime.converse(
        modelId=endpoint_arn,
        messages=[{
            'role': 'user',
            'content': [{'text': 'Reply with the single word hello.'}],
        }],
        # This TGI-backed marketplace endpoint rejects temperature=0
        # ("must be strictly positive"), unlike the native Bedrock
        # inference-profile invocation path.
        inferenceConfig={'maxTokens': 8, 'temperature': 0.01},
    )


def wait_for_invocation_metric(session_factory, endpoint_arn, test):
    if not test.recording:
        return
    from datetime import datetime, timedelta, timezone

    cloudwatch = session_factory().client('cloudwatch', region_name=REGION)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc)
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/Bedrock',
            MetricName='Invocations',
            Dimensions=[{'Name': 'ModelId', 'Value': endpoint_arn}],
            StartTime=end - timedelta(hours=1),
            EndTime=end,
            Period=60,
            Statistics=['Sum'],
        )
        if response['Datapoints']:
            return
        time.sleep(15)
    raise TimeoutError('timed out waiting for Bedrock Invocations metric')


@terraform('bedrock_marketplace_model_endpoint', replay=False)
def test_bedrock_marketplace_model_endpoint(
        test, bedrock_marketplace_model_endpoint, create_marketplace_model_endpoint):
    """Status filter and Invocations-metric checks against a single endpoint.

    One test, one recorded endpoint: CreateMarketplaceModelEndpoint
    provisions a real, dedicated SageMaker instance (see the fixture
    README), so this shares one create/delete cycle across both checks
    rather than paying for it twice.
    """
    execution_role_arn = bedrock_marketplace_model_endpoint.outputs[
        'execution_role_arn']['value']

    test.session_factory = test.record_flight_data(
        'bedrock_marketplace_model_endpoint', region=REGION)

    endpoint_arn = create_marketplace_model_endpoint(execution_role_arn)

    status_policy = test.load_policy(
        {
            'name': 'bedrock-marketplace-model-endpoint-registered',
            'resource': 'aws.bedrock-marketplace-model-endpoint',
            'filters': [{'status': 'REGISTERED'}],
        },
        session_factory=test.session_factory,
        config={'region': REGION},
    )
    resources = status_policy.run()
    assert any(r['endpointArn'] == endpoint_arn for r in resources)

    emit_invocation(test.session_factory, endpoint_arn)
    wait_for_invocation_metric(test.session_factory, endpoint_arn, test)

    def run_invocations_policy(value, op):
        policy = test.load_policy(
            {
                'name': 'bedrock-marketplace-model-endpoint-invocations',
                'resource': 'aws.bedrock-marketplace-model-endpoint',
                'filters': [
                    {'endpointArn': endpoint_arn},
                    {
                        'type': 'metrics',
                        'name': 'Invocations',
                        'days': 1,
                        'period': 300,
                        'value': value,
                        'op': op,
                    },
                ],
            },
            session_factory=test.session_factory,
            config={'region': REGION},
        )
        return policy.run()

    resources = run_invocations_policy(0, 'greater-than')
    assert len(resources) == 1
    assert resources[0]['endpointArn'] == endpoint_arn

    resources = run_invocations_policy(1000000, 'greater-than')
    assert resources == []
