# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from pytest_terraform import terraform


# @terraform('vertexai_endpoint')
def test_vertexai_endpoint_default(test):
    session_factory = test.record_flight_data('vertexai-endpoint-default')

    policy = test.load_policy(
        {'name': 'vertexai-endpoints',
         'resource': 'gcp.vertexai-endpoint'},
        session_factory=session_factory)

    resources = policy.run()
    assert len(resources) == 2


# TODO: test passing location via: config region, policy itself, and [any other ways?]

# TODO: test audit policy (get method implemented)
