# App Engine Service Version Recording

This fixture deploys two App Engine standard versions to the `default` service:
one whose `/.*` handler is `SECURE_ALWAYS` and one whose handler is
`SECURE_OPTIONAL`.

## Prerequisites

App Engine won't delete these, so the fixture can't manage them:

- **An App Engine application.** Applications can't be deleted and their region
  can't change, so a fixture that created one could only ever apply once.

  ```bash
  gcloud app create --region=us-central
  ```

- **A version in `default` that isn't from this fixture.** App Engine refuses to
  delete the last version of a service ("Cannot delete the final version of a
  service"). In a new app, the first recording's destroy fails on one version.
  Remove it from state, destroy the rest, and leave that version in place.
  Later recordings tear down cleanly.

- **APIs enabled:**

  ```bash
  gcloud services enable appengine.googleapis.com cloudbuild.googleapis.com \
    storage.googleapis.com artifactregistry.googleapis.com
  ```

## Recording

Switch both `test_app_engine_service_version_*` tests in `test_appengine.py` to
`replay=False` and `record_flight_data`, then run:

```bash
GOOGLE_CLOUD_PROJECT=<project> uv run pytest -s -p no:env --tf-debug \
  tools/c7n_gcp/tests/test_appengine.py -k app_engine_service_version
```

The recorder only rewrites `projects/<id>/`, and App Engine paths are
`apps/<id>/`. Before committing:

- rename the flight files and replace the project id with `cloud-custodian`, in
  the flight data and in `tf_resources.json`
- replace `createdBy` with `user@example.com`, and the bucket's `project_number`
  in `tf_resources.json` with `123456789012`

## Cleanup check

```bash
gcloud app versions list --project <project>
gcloud storage buckets list --project <project> --filter='name~c7n-app-engine'
```

Only the long-lived `default` version should remain, and no `c7n-app-engine-*`
bucket.
