# Vertex AI Tuned-Model Distribution Metric Recording

This fixture has no Terraform module: a supervised fine-tuning job creates
its own `Model` and `Endpoint` resources, so there's nothing to provision
ahead of time. To record
`test_vertexai_endpoint_tuned_model_tokens_metric`, you need to run a real
tuning job, send it a few predictions, and wait for
`aiplatform.googleapis.com/tuned_model/online_serving/tokens` to appear.

Verified against the project's live metric descriptor: this metric is
`DELTA`/`DISTRIBUTION`, keyed to the `aiplatform.googleapis.com/Endpoint`
monitored resource, with a `request_type` label distinguishing `dedicated`
(paid provisioned throughput) from `shared` (default). This fixture uses
the default shared serving path, so there's no dedicated compute node to
pay for by the hour -- billing is per-token, at the tuned model's base-model
rate.

## Prerequisites

- Application default credentials configured for the target GCP project
  (`gcloud auth application-default login`)
- Python dependencies installed:

```bash
uv pip install google-cloud-storage google-auth requests
```

- Confirm the base model in `run_tuning.py` (`gemini-2.5-flash` by
  default) is still listed as tunable at
  https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/tuning#supported_models
  before running -- supported models change over time. Don't probe
  candidate names by POSTing to `tuningJobs.create`: that call has no
  dry-run mode and creates a real job on every attempt.

## Recording Workflow

1. Add a breakpoint at the top of
   `test_vertexai_endpoint_tuned_model_tokens_metric`, before
   `session_factory = test.replay_flight_data(...)`. Add a second
   breakpoint at the end of the test function.
2. Start the test in record mode.
3. When the test stops at the breakpoint, run:

```bash
python tools/c7n_gcp/tests/terraform/vertexai_tuned_model_metrics/run_tuning.py
```

   This uploads `training_data.jsonl` to the project's default Vertex AI
   staging bucket, creates the tuning job, and polls until it succeeds,
   printing the resulting `endpoint` and `model` resource names. Tuning
   job duration varies; check progress via the printed state transitions
   rather than assuming a fixed time.

4. Run:

```bash
python tools/c7n_gcp/tests/terraform/vertexai_tuned_model_metrics/generate_traffic_and_wait.py <endpoint-from-step-3>
```

   This sends a few `generateContent` calls to the tuned model and polls
   Cloud Monitoring until the metric appears, instead of sleeping a fixed
   guess -- see the lesson in the sibling `publisher-model-metrics`
   fixture, where the documented 20-30 minute propagation estimate turned
   out to be under 2 minutes in practice.

5. Return to the test and continue execution.
6. When the test stops at the second breakpoint, run:

```bash
python tools/c7n_gcp/tests/terraform/vertexai_tuned_model_metrics/cleanup.py \
    <tuning-job-name-from-step-3> <endpoint-from-step-3> <model-from-step-3>
```

7. Commit the resulting `tests/data/flights/<flight-name>/` alongside the
   test.
