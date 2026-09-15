# Bedrock Marketplace model endpoint recording

Backs `test_bedrock_marketplace_model_endpoint` in
`tests/test_bedrock_marketplace.py`, which checks the `status` value filter
and a `metrics` filter on the `Invocations` metric against a single created
endpoint.

This originally checked a `metrics` filter's derived `c7n:TotalTokenCount`
(summing `InputTokenCount` + `OutputTokenCount` via CloudWatch metric math,
the same pattern as `InferenceProfileMetrics` on
`aws.bedrock-inference-profile`). That filter and its test were removed
after live recording confirmed AWS never publishes those two metrics for
Bedrock Marketplace endpoints -- see "Token metrics are not available"
below. `Invocations` is the replacement: real, published data, but a coarser
volume proxy than a token count since it ignores prompt/response length.
See the tracking issue for the up-to-date status of the token-count gap.

## Why the endpoint is not a Terraform resource

The AWS provider has no Bedrock Marketplace endpoint resource at all --
tracked upstream as
[hashicorp/terraform-provider-aws#41370](https://github.com/hashicorp/terraform-provider-aws/issues/41370),
open and unimplemented. Unlike `bedrock_inference_profile_token_metrics`
(where Terraform owns the profile and only the runtime invocation is
ephemeral) or `bedrock_deployable_custom_model` (where Terraform owns the
transient prerequisites but not the long-lived model), here Terraform can
express **only** the SageMaker execution role the endpoint config requires.
Everything else -- create, wait for `InService`/`REGISTERED`, and delete --
happens through the API in the `create_marketplace_model_endpoint` pytest
fixture (`tests/test_bedrock_marketplace.py`).

## Token metrics are not available

Confirmed live (2026-09): `aws cloudwatch list-metrics --namespace
AWS/Bedrock --dimensions Name=ModelId,Value=<endpoint arn>` returns only
`Invocations`, `InvocationClientErrors`, `InvocationLatency`, and
`EstimatedTPMQuotaUsage` for a Bedrock Marketplace endpoint -- no
`InputTokenCount`/`OutputTokenCount` metric definitions at all, under any
dimension. This isn't a timing issue: `Invocations` itself returned a real
datapoint for the same invocation, confirming the CloudWatch pipeline,
dimension value, and metrics-publishing path all work correctly -- the
token-count metrics are simply never published for this invocation path,
unlike native Bedrock foundation-model/inference-profile invocations (where
`bedrock_inference_profile_token_metrics` confirms they are). The original
benchmark's own text flagged this as inferred, not confirmed, for
marketplace endpoints specifically -- this recording session settled it.

## Cost

`CreateMarketplaceModelEndpoint` provisions a real, dedicated SageMaker
inference instance that bills per instance-hour for as long as the endpoint
exists, per the AWS docs. This is not on-demand serverless deployment (unlike
`aws.bedrock-custom-model`'s deployments filter fixture) -- the instance runs
continuously from creation until deletion. Endpoint creation and deletion each
take on the order of 10-15 minutes per AWS's documented timeline. Pick the
smallest viable instance type for the subscribed model, and confirm the
fixture tears the endpoint down (`DeleteMarketplaceModelEndpoint`) even on
failure before ending a recording session.

## Prerequisite: pick a model

Since the token-metrics filter is gone, Converse-API support is no longer a
requirement -- any free, registerable model works for the status-filter
check. `./list_free_models.py` still helps pick one and, notably, surfaces
`default_instance`/`supported_instances` per model (from
`HubContentDocument.DefaultInferenceInstanceType`/
`SupportedInferenceInstanceTypes`) -- useful because a smaller model does
**not** imply a smaller required instance in this catalog. For example
`granite-3-0-2b-instruct` (2B params) requires `ml.p4d.24xlarge` (8x A100),
while `huggingface-llm-mistral-7b-openorca-gptq` (7B params, this fixture's
default) only needs `ml.g5.xlarge` (1 GPU) -- confirm actual instance
requirements before assuming smaller-params-means-cheaper:

```bash
tests/terraform/bedrock_marketplace_model_endpoint/list_free_models.py \
  --region us-east-1 --eula-status no-eula
```

`--name-contains` is repeatable, to check several vendors' open-weight
offerings in one pass (each value is matched server-side, results merged and
de-duplicated):

```bash
tests/terraform/bedrock_marketplace_model_endpoint/list_free_models.py \
  --region us-east-1 \
  --name-contains openai --name-contains gpt-oss --name-contains claude
```

Claude won't turn up under any vendor term -- Bedrock serves it as a native
foundation model, not through this SageMaker JumpStart hub.

Open-weight/gated models need no AWS Marketplace subscription -- pass
`acceptEula=True` on `CreateMarketplaceModelEndpoint` for a gated one and
that's the whole requirement. There is no API field marking a model "free":
paid, private-offer marketplace listings aren't returned by this script's
filter reliably and must be recognized by name/vendor -- avoid those for this
fixture. Note the chosen model's `HubContentArn` (the
`modelSourceIdentifier`), of the form:

```
arn:aws:sagemaker:<region>:aws:hub-content/SageMakerPublicHub/Model/<model-name>/<version>
```

This choice determines cost and instance-type eligibility and should be
confirmed with the account owner before recording -- it is not something to
pick unilaterally.

`tests/test_bedrock_marketplace.py` defaults to a model already confirmed
this way (`huggingface-llm-mistral-7b-openorca-gptq`, free, cheapest instance
found in the survey). Since this catalog's models are added and removed over
time, override it at test run without editing the test:

```bash
MARKETPLACE_MODEL_SOURCE_IDENTIFIER="arn:aws:sagemaker:<region>:aws:hub-content/SageMakerPublicHub/Model/<model-name>/<version>" \
MARKETPLACE_ENDPOINT_INSTANCE_TYPE="ml.g5.xlarge" \
  uv run pytest -s -p no:env --tf-debug \
  tests/test_bedrock_marketplace.py::test_bedrock_marketplace_model_endpoint
```

## Recording

1. Temporarily add `replay=False` to the
   `@terraform("bedrock_marketplace_model_endpoint")` decorator on
   `test_bedrock_marketplace_model_endpoint` and switch
   `test.replay_flight_data(...)` to `test.record_flight_data(...)`.
2. Run the focused test with `-s -p no:env --tf-debug`. pytest-terraform
   applies this fixture's execution role and passes its output to the test as
   `bedrock_marketplace_model_endpoint.outputs['execution_role_arn']['value']`.
   The `create_marketplace_model_endpoint` fixture calls
   `CreateMarketplaceModelEndpoint` with the subscribed model's hub-content
   ARN and that role, polls `GetMarketplaceModelEndpoint` until
   `endpointStatus` is `InService` and `status` is `REGISTERED`, and yields
   the endpoint ARN, used for the status-filter assertion.
3. The test then invokes the same endpoint through `bedrock-runtime converse`
   (model id = the endpoint ARN; `temperature` must be > 0 for this
   TGI-backed model) and polls CloudWatch for the `Invocations` metric before
   recording the `Invocations`-filter assertions.
4. The fixture deletes the endpoint (`DeleteMarketplaceModelEndpoint`) on
   teardown regardless of test outcome; pytest-terraform destroys the
   execution role afterward.
5. Restore `replay_flight_data` and remove `replay=False`, then verify with
   `C7N_FUNCTIONAL=no uv run pytest ...`.

Inspect recorded flight data for account IDs, role names, and endpoint ARNs
before committing.
