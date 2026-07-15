# Bedrock evaluation job test fixture

The AWS Terraform provider and CloudFormation cannot create a Bedrock evaluation job. This
fixture therefore uses the ephemeral-resource exception from `testing.md`: Terraform owns the
IAM role and output bucket, while `setup.py` and `cleanup.py` manage only the evaluation job.

## Recording

Prerequisites are AWS credentials with permission to manage the Terraform resources, pass the
fixture role, use the Bedrock evaluation APIs, and invoke Amazon Nova Micro in `us-east-1`.

Temporarily configure both tests with `replay=False`,
`teardown=terraform.TEARDOWN_OFF`, and `record_flight_data`. Apply the Terraform fixture without
running either test:

```shell
uv run pytest -s -p no:env --tf-debug --setup-only \
  tests/test_bedrock.py -k bedrock_evaluation_job
```

The command exits after Terraform apply. Save the Terraform binary, `TF_DATA_DIR`, working
directory, and state path printed by `--tf-debug`. From this fixture directory, read the live
outputs without using the sanitized `tf_resources.json`:

```shell
TF_DATA_DIR=PRINTED_TF_DATA_DIR PRINTED_TERRAFORM_BIN output -json \
  -state=PRINTED_STATE_PATH
```

Pass the returned `job_name`, `model_arn`, `output_s3_uri`, and `role_arn` values to the setup
script:

```shell
uv run python tests/terraform/bedrock_evaluation_job/setup.py \
  --job-name JOB_NAME \
  --model-arn MODEL_ARN \
  --output-s3-uri OUTPUT_S3_URI \
  --role-arn ROLE_ARN
```

Temporarily use `replay=True` on both decorators while retaining `record_flight_data`, then record
both tests against the preserved Terraform resources and live evaluation job:

```shell
uv run pytest -s -p no:env tests/test_bedrock.py -k bedrock_evaluation_job
```

After successful recording, delete the job while its Terraform dependencies still exist:

```shell
uv run python tests/terraform/bedrock_evaluation_job/cleanup.py --job-name JOB_NAME
```

Finally, use the Terraform/OpenTofu executable, working directory, `TF_DATA_DIR`, and state path
printed by `--tf-debug` to run the mandatory manual destroy described in `testing.md`.

Remove all recording-only options, change both tests to `replay_flight_data`, and verify the
finished group:

```shell
uv run pytest tests/test_bedrock.py -k bedrock_evaluation_job
```
