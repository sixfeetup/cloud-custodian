# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from google.api_core.client_options import ClientOptions

from c7n.utils import local_session, jmespath_search
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo


REGION_DATA_PATH = Path(__file__).parent.parent / 'regions.json'


@resources.register('vertex-ai-location')
class VertexAILocation:
    """Vertex AI Location pseudo-resource for multi-location enumeration.

    This is used internally by VertexAIEndpoint to support querying multiple locations.
    Loads available GCP regions from regions.json and filters to Vertex AI supported regions.
    """

    class resource_type(TypeInfo):
        name = id = 'name'
        scope = 'global'
        default_report_fields = ['name']
        service = 'vertex-ai-locations'

    filter_registry = {}
    action_registry = {}

    # Vertex AI supported regions as of 2024
    # Based on: https://cloud.google.com/vertex-ai/docs/general/locations
    _vertex_ai_regions = {
        'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
        'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
        'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast3', 'asia-southeast1',
        'australia-southeast1', 'northamerica-northeast1', 'southamerica-east1'
    }

    def __init__(self, ctx=None, data=()):
        self.ctx = ctx
        self.config = ctx.options if ctx else None
        self.data = data

        # Load all GCP regions from regions.json
        with open(REGION_DATA_PATH) as fh:
            all_regions = json.load(fh)

        # Filter to only Vertex AI supported regions
        self.regions = [r for r in all_regions if r in self._vertex_ai_regions]

    def get_permissions(self):
        return ()

    def resources(self, resource_ids=()):
        """Return list of Vertex AI locations to query.

        Locations can be specified via:
        1. Policy query: {'query': [{'name': 'us-central1'}, {'name': 'us-east1'}]}
                     or: {'query': [{'location': 'us-central1'}, {'location': 'us-east1'}]}
        2. Config regions: --regions us-central1,us-east1
        3. Config region: --region us-central1
        4. Default: All Vertex AI supported regions from regions.json
        """
        # If specific resource IDs requested, filter to those
        if resource_ids:
            return [{'name': r} for r in self.regions if r in resource_ids]

        # If query specified in policy, use those locations
        if 'query' in self.data:
            query_locations = set()
            for q in self.data['query']:
                # Support both 'name' and 'location' keys
                if 'name' in q:
                    query_locations.add(q['name'])
                elif 'location' in q:
                    query_locations.add(q['location'])
            return [{'name': loc} for loc in self.regions if loc in query_locations]

        # If config regions specified, use those
        if self.config and self.config.regions and 'all' not in self.config.regions:
            return [{'name': r} for r in self.regions if r in self.config.regions]

        # If single config region specified, use that
        if self.config and self.config.region and self.config.region != 'us-east-1':
            return [{'name': self.config.region}] if self.config.region in self.regions else []

        # Default: return all Vertex AI supported regions
        return [{'name': loc} for loc in self.regions]


@resources.register('vertex-ai-endpoint')
class VertexAIEndpoint(QueryResourceManager):
    """GCP Vertex AI Endpoint Resource

    Vertex AI Endpoints are used to deploy machine learning models for online prediction.

    :example:

    List all Vertex AI Endpoints in specific locations:

    .. code-block:: yaml

        policies:
          - name: vertexai-endpoints-missing-env-label
            resource: gcp.vertex-ai-endpoint
            query:
              - name: us-central1
              - name: us-east1
            filters:
              - type: value
                key: labels.env
                op: absent

    :example:

    List all Vertex AI Endpoints across all locations:

    .. code-block:: yaml

        policies:
          - name: vertexai-endpoints-all-locations
            resource: gcp.vertex-ai-endpoint
    """

    class resource_type(TypeInfo):
        service = 'aiplatform'
        version = 'v1'
        component = 'projects.locations.endpoints'
        enum_spec = ('list', 'endpoints[]', None)
        scope = 'project'
        scope_key = 'parent'
        scope_template = None  # Handled dynamically per location
        name = id = 'name'
        default_report_fields = [
            'name', 'displayName', 'deployedModels[].displayName', 'createTime', 'updateTime'
        ]
        asset_type = 'aiplatform.googleapis.com/Endpoint'
        permissions = ('aiplatform.endpoints.list',)
        urn_component = 'endpoint'
        urn_id_segments = (-1,)

        @staticmethod
        def get(client, resource_info):
            # Resource name format: projects/{project}/locations/{location}/endpoints/{endpoint}
            return client.execute_query(
                'get', {'name': resource_info['resourceName']})

        @classmethod
        def _get_location(cls, resource):
            """Extract location from resource name."""
            # Resource name format: projects/{project}/locations/{location}/endpoints/{endpoint}
            return resource['name'].split('/')[3]

    def _fetch_resources(self, query):
        """Override to handle location-specific API endpoints and multi-location enumeration.

        Vertex AI requires:
        1. Location-specific hostnames (e.g., us-central1-aiplatform.googleapis.com)
        2. Location in the parent scope (e.g., projects/{project}/locations/{location})
        3. Enumeration across multiple locations (similar to RegionalResourceManager)
        """
        if not query:
            query = {}

        session = local_session(self.session_factory)
        project = session.get_default_project()

        # Get locations to query
        location_query = self._get_location_query()
        location_manager = self.get_resource_manager(
            resource_type='vertex-ai-location',
            data=({'query': location_query} if location_query else {})
        )

        all_resources = []
        annotation_key = 'c7n:location'

        # Enumerate resources in each location
        for location_instance in location_manager.resources():
            location = location_instance['name']

            # Build location-specific API endpoint (must include https:// scheme)
            api_endpoint = f'https://{location}-aiplatform.googleapis.com'
            client_options = ClientOptions(api_endpoint=api_endpoint)

            # Get client with location-specific endpoint
            client = session.client(
                self.resource_type.service,
                self.resource_type.version,
                self.resource_type.component,
                client_options=client_options
            )

            # Build the parent scope with project and location
            parent = f'projects/{project}/locations/{location}'

            # Execute the list operation for this location
            enum_op, path, extra_args = self.resource_type.enum_spec
            params = {'parent': parent}
            if extra_args:
                params.update(extra_args)

            # Invoke the client enumeration
            location_resources = []
            if client.supports_pagination(enum_op):
                for page in client.execute_paged_query(enum_op, params):
                    page_items = jmespath_search(path, page)
                    if page_items:
                        location_resources.extend(page_items)
            else:
                location_resources = jmespath_search(
                    path, client.execute_query(enum_op, verb_arguments=params)) or []

            # Annotate resources with their location
            for resource in location_resources:
                resource[annotation_key] = location_instance

            all_resources.extend(location_resources)

        return all_resources

    def _get_location_query(self):
        """Get location query for multi-location enumeration.

        Returns query to pass to vertex-ai-location resource manager.
        If policy has 'query' specified, use that to filter locations.
        Otherwise, return None to use default location logic.

        Returns:
            list or None: Location query list or None for defaults
        """
        # If policy has query specified, pass it through to location manager
        if 'query' in self.data:
            return self.data['query']

        # Otherwise, let location manager use config.regions or config.region
        return None
