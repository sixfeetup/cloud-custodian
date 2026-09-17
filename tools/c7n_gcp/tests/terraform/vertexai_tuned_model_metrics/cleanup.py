#!/usr/bin/env python3
"""Delete the tuned model, its endpoint, and the tuning job created by
run_tuning.py. Best-effort: reports failures instead of raising, since
partial cleanup shouldn't block finishing the recording session.

Usage:
    python cleanup.py <tuning-job-name> <endpoint-resource-name> <model-resource-name>
"""
import sys

import google.auth
from google.auth.transport.requests import AuthorizedSession

LOCATION = "us-central1"


def delete(session, resource_name, label):
    url = f"https://{LOCATION}-aiplatform.googleapis.com/v1/{resource_name}"
    resp = session.delete(url, timeout=30)
    if resp.ok:
        print(f"deleted {label}: {resource_name}", file=sys.stderr)
    else:
        print(f"failed to delete {label} {resource_name}: {resp.status_code} {resp.text}",
              file=sys.stderr)


def main():
    tuning_job, endpoint, model = sys.argv[1:4]

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = AuthorizedSession(credentials)

    # Model version, then endpoint, then the tuning job record itself.
    delete(session, model, "tuned model")
    delete(session, endpoint, "endpoint")
    delete(session, tuning_job, "tuning job")


if __name__ == "__main__":
    main()
