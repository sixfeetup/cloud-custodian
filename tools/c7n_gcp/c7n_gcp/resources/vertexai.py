# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo, ChildResourceManager, ChildTypeInfo


# Known Vertex AI Model Garden publishers
# This list is maintained based on available publishers in the Model Garden
# Add new publishers as they become available
VERTEX_AI_PUBLISHERS = [
    'google',
    'anthropic',
    'meta',
    'mistralai',
    'cohere',
    # Add more publishers as they become available in Model Garden
]


@resources.register('vertex-ai-publisher')
class VertexAIPublisher(QueryResourceManager):
    """GCP Resource for Vertex AI Model Garden Publishers

    This resource provides a list of known publishers in Vertex AI Model Garden.
    It serves as a parent resource for vertex-ai-publisher-model.

    Note: This is a synthetic resource based on known publishers, not an API endpoint.
    The list of publishers is maintained in the VERTEX_AI_PUBLISHERS constant.

    :example: List all Vertex AI publishers

    .. code-block:: yaml

        policies:
          - name: vertex-ai-publishers
            resource: gcp.vertex-ai-publisher
    """

    class resource_type(TypeInfo):
        service = 'aiplatform'
        version = 'v1beta1'
        component = 'publishers'
        scope = 'global'
        name = id = 'name'
        default_report_fields = ['name']
        permissions = ()  # No specific permissions needed for synthetic resource
        urn_component = 'publisher'

    def resources(self, query=None):
        """Return synthetic publisher resources."""
        # Create synthetic resources for each known publisher
        return [{'name': f'publishers/{publisher}'} for publisher in VERTEX_AI_PUBLISHERS]


@resources.register('vertex-ai-publisher-model')
class VertexAIPublisherModel(ChildResourceManager):
    """GCP Resource for Vertex AI Model Garden Publisher Models

    https://cloud.google.com/vertex-ai/docs/reference/rest/v1beta1/publishers.models

    This resource provides access to the Vertex AI Model Garden catalog of
    publisher models from all known publishers (Google, Anthropic, Meta, etc.).

    Note: Uses v1beta1 API because v1 does not support list operations.
    As of 2026-03, the v1 API only has 'get' method for publishers.models.
    When v1 adds list support, migrate to v1 (expect 180-day deprecation notice
    per Google Cloud's beta API policy: https://google.aip.dev/185).

    :example: List all Vertex AI publisher models from all publishers

    .. code-block:: yaml

        policies:
          - name: vertex-ai-publisher-models
            resource: gcp.vertex-ai-publisher-model

    :example: List only Anthropic models

    .. code-block:: yaml

        policies:
          - name: anthropic-models
            resource: gcp.vertex-ai-publisher-model
            filters:
              - type: value
                key: name
                op: regex
                value: 'publishers/anthropic/.*'
    """

    def get_permissions(self):
        """Override to return empty permissions - catalog is publicly readable."""
        return ()

    def _get_child_enum_args(self, parent_instance):
        """Extract parent parameter for listing models."""
        return {'parent': parent_instance['name']}

    class resource_type(ChildTypeInfo):
        service = 'aiplatform'
        # TODO: Migrate to v1 when list support is added
        version = 'v1beta1'
        # version = 'v1'  # Uncomment when v1 supports list operations

        component = 'publishers.models'
        enum_spec = ('list', 'publisherModels[]', None)
        scope = 'global'
        name = id = 'name'
        default_report_fields = [
            'name', 'versionId', 'publisherModelTemplate', 'launchStage']
        # No specific permissions - publisher models catalog is publicly readable
        permissions = ()
        urn_component = 'publisher-model'
        urn_id_segments = (-1,)
        parent_spec = {'resource': 'vertex-ai-publisher'}
