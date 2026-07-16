# Bedrock evaluation job test fixture

The AWS Terraform provider and CloudFormation cannot create a Bedrock evaluation job. This
fixture therefore uses the ephemeral-resource exception from `testing.md`: Terraform owns the
IAM role, output bucket, and lifecycle configuration, while `setup.py` and `cleanup.py` manage
only the evaluation job.

## Prerequisites and permissions

Use AWS credentials that can create, read, update, and delete the fixture's S3 bucket and
lifecycle configuration, IAM role and inline policy, and random ID. The identity must also be
able to pass the fixture role, use the Bedrock evaluation-job APIs, tag evaluation jobs, and
invoke Amazon Nova Micro in `us-east-1`. Bedrock model access must be enabled for the account.
Terraform/OpenTofu, `uv`, and the repository test dependencies must be installed.

## Recording

Temporarily set every `@terraform('bedrock_evaluation_job', ...)` decorator to
`replay=False, teardown=terraform.TEARDOWN_OFF, scope='session'`, and change every test to its
unique `record_flight_data` call. Provision the dependencies without running tests:

```shell
uv run pytest -s -p no:env --tf-debug --setup-only \
  tests/test_bedrock.py -k bedrock_evaluation_job
```

Save the Terraform/OpenTofu binary, module directory, `TF_DATA_DIR`, and state path printed by
`--tf-debug`. Retain those exact paths until cleanup and destroy have both succeeded. Read the
unsanitized live outputs directly from the state, from the saved module directory:

```shell
TF_DATA_DIR=PRINTED_TF_DATA_DIR PRINTED_TERRAFORM_BIN output -json \
  -state=PRINTED_STATE_PATH
```

Never pass identities from the sanitized committed `tf_resources.json` to a live API. Pass the
live `job_name`, `model_arn`, `output_s3_uri`, and `role_arn` values to the setup script:

```shell
uv run python tests/terraform/bedrock_evaluation_job/setup.py \
  --job-name JOB_NAME \
  --model-arn MODEL_ARN \
  --output-s3-uri OUTPUT_S3_URI \
  --role-arn ROLE_ARN
```

Temporarily switch every decorator to `replay=True`, remove
`teardown=terraform.TEARDOWN_OFF`, retain `scope='session'` and each unique
`record_flight_data` call, then record the complete group:

```shell
uv run pytest -s -p no:env tests/test_bedrock.py -k bedrock_evaluation_job
```

Cleanup must happen before destroy. Delete the ephemeral job while all Terraform dependencies
still exist, and do not continue until it is deleted or confirmed absent:

```shell
uv run python tests/terraform/bedrock_evaluation_job/cleanup.py --job-name JOB_NAME
```

Then change to the saved module directory and destroy with the exact saved paths:

```shell
TF_DATA_DIR=PRINTED_TF_DATA_DIR PRINTED_TERRAFORM_BIN destroy \
  -input=false -no-color -state=PRINTED_STATE_PATH -auto-approve
```

Confirm that no evaluation job, bucket, role, policy, or lifecycle configuration remains.
Convert all tests to committed form: retain `scope='session'`, remove both `replay` and
`teardown`, and use each test's unique `replay_flight_data` call. Commit the regenerated
`tf_resources.json` and every refreshed or new flight-data directory after inspecting them for
credentials, unsanitized account/provider identities, and recording-only settings.

Force replay and run the entire shared-fixture group:

```shell
C7N_FUNCTIONAL=no uv run pytest tests/test_bedrock.py -k bedrock_evaluation_job
```

## Failure recovery

If apply, setup, recording, or any test fails, retain the printed Terraform/OpenTofu binary,
module directory, `TF_DATA_DIR`, and state path. If setup created an evaluation job, run
`cleanup.py --job-name JOB_NAME` first and confirm deletion; do not destroy the job's bucket,
role, policy, or lifecycle configuration until cleanup succeeds. Then run the exact destroy
command above from the saved module directory. Restart recording from a fresh apply rather than
reusing partial state or flight data, and never send sanitized `tf_resources.json` identities
to live APIs.
