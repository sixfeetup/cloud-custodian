# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from googleapiclient.errors import HttpError

from c7n.utils import jmespath_search, local_session
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo, extract_errors
from c7n_gcp.region import Region

log = logging.getLogger('c7n_gcp.resources.vertexai')


@resources.register('vertexai-endpoint')
class VertexAIEndpoint(QueryResourceManager):
    """GCP resource: https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.endpoints

    :example:

    Find endpoints missing an environment label.

    .. code-block:: yaml

        policies:
          - name: vertexai-endpoints-missing-env-label
            resource: gcp.vertexai-endpoint
            filters:
              - type: value
                key: labels.env
                op: absent
    """

    def __init__(self, ctx, data):
        print("Initializing vertexai-endpoint resource")
        super().__init__(ctx, data)
        self._client_cache = {}

    class resource_type(TypeInfo):
        service = 'aiplatform'
        version = 'v1'
        component = 'projects.locations.endpoints'
        enum_spec = ('list', 'endpoints[]', None)
        scope = 'project'
        scope_key = 'parent'
        name = id = 'name'
        default_report_fields = [
            'name', 'displayName', 'createTime', 'updateTime'
        ]
        asset_type = 'aiplatform.googleapis.com/Endpoint'
        urn_component = 'endpoint'
        urn_id_segments = (-1,)
        # TODO: labels
        # TODO: support server-side "filter"

        @staticmethod
        def get(client, resource_info):
            name = (
                'projects/{}/locations/{}/endpoints/{}'
                .format(resource_info['project_id'],
                        resource_info['location'],
                        resource_info['endpoint_id'])
            )
            return client.execute_query('get', verb_arguments={'name': name})

        @classmethod
        def _get_location(cls, resource):
            return resource['name'].split('/')[3]

    def get_resource_query(self):
        return self.data.get('query')

    def _fetch_resources(self, query):
        session = local_session(self.session_factory)
        project = session.get_default_project()
        locations = self._get_locations(query)
        enum_op, path, extra_args = self.resource_type.enum_spec
        query_params = self._get_query_params(query)

        resources = []
        for location in locations:
            print("Fetching vertex ai endpoints in %s for %s", location, project)
            client = self._get_location_client(session, location)
            params = {
                'parent': 'projects/{}/locations/{}'.format(project, location)
            }
            if extra_args:
                params.update(extra_args)
            if query_params:
                params.update(query_params)
            try:
                resources.extend(self._invoke_client_enum(client, enum_op, params, path))
            except HttpError as e:
                if self._handle_http_error(e, location, project):
                    continue
                raise
        return resources

    def _get_locations(self, query):
        locations = self._get_locations_from_query(query)
        if locations:
            return locations

        locations = self._get_locations_from_config()
        if locations:
            return locations

        session = local_session(self.session_factory)
        project = session.get_default_project()
        locations = self._get_available_locations(session, project)
        if locations:
            return locations

        return [r['name'] for r in Region(self.ctx).resources()]

    def _get_available_locations(self, session, project):
        client = session.client(
            self.resource_type.service,
            self.resource_type.version,
            'projects.locations',
            discoveryServiceUrl=self._get_discovery_url('global'))
        try:
            response = client.execute_query(
                'list', verb_arguments={'name': f'projects/{project}'})
        except HttpError as e:
            if self._handle_locations_http_error(e, project):
                return []
            raise

        locations = []
        for location in response.get('locations', ()):
            location_id = location.get('locationId')
            if not location_id:
                name = location.get('name')
                if name:
                    location_id = name.rsplit('/', 1)[-1]
            if location_id:
                locations.append(location_id)
        return self._normalize_locations(locations)

    def _get_locations_from_query(self, query):
        if not query:
            return []

        if isinstance(query, dict):
            return self._normalize_locations(
                query.get('locations') or query.get('location'))

        if isinstance(query, list):
            locations = []
            for item in query:
                if not isinstance(item, dict):
                    continue
                if 'location' in item or 'locations' in item:
                    locations.extend(self._normalize_locations(
                        item.get('locations') or item.get('location')))
            return self._normalize_locations(locations)

        return []

    def _get_locations_from_config(self):
        if self.config.regions:
            if 'all' not in self.config.regions:
                return self._normalize_locations(self.config.regions)
            return []

        if self.config.region:
            return self._normalize_locations([self.config.region])

        return []

    @staticmethod
    def _normalize_locations(locations):
        if not locations:
            return []
        if isinstance(locations, str):
            locations = [locations]
        locations = [l for l in locations if l]
        if not locations:
            return []
        if locations == ['us-east-1']:
            return []
        if 'us-east-1' in locations:
            locations = [l for l in locations if l != 'us-east-1']
        normalized = []
        for location in locations:
            if location not in normalized:
                normalized.append(location)
        return normalized

    @staticmethod
    def _get_query_params(query):
        if not isinstance(query, dict):
            return {}
        params = dict(query)
        params.pop('location', None)
        params.pop('locations', None)
        return params

    def _get_location_client(self, session, location):
        client = self._client_cache.get(location)
        if client:
            return client
        discovery_url = self._get_discovery_url('global')
        api_endpoint = self._get_api_endpoint(location)
        client = session.client(
            self.resource_type.service,
            self.resource_type.version,
            self.resource_type.component,
            discoveryServiceUrl=discovery_url,
            client_options={'api_endpoint': api_endpoint})
        self._client_cache[location] = client
        return client

    @staticmethod
    def _get_service_endpoint(location):
        if not location or location == 'global':
            return 'aiplatform.googleapis.com'
        return '{}-aiplatform.googleapis.com'.format(location)

    @classmethod
    def _get_api_endpoint(cls, location):
        endpoint = cls._get_service_endpoint(location)
        return 'https://{}/v1/'.format(endpoint)

    @classmethod
    def _get_discovery_url(cls, location):
        endpoint = cls._get_service_endpoint(location)
        return 'https://{}/$discovery/rest?version=v1'.format(endpoint)

    @staticmethod
    def _invoke_client_enum(client, enum_op, params, path):
        if client.supports_pagination(enum_op):
            results = []
            for page in client.execute_paged_query(enum_op, params):
                page_items = jmespath_search(path, page)
                if page_items:
                    results.extend(page_items)
            return results
        return jmespath_search(
            path, client.execute_query(enum_op, verb_arguments=params))

    def _handle_http_error(self, error, location, project):
        error_reason, error_code, error_message = extract_errors(error)
        status = getattr(error.resp, 'status', None)
        if error_code in (400, 404) or status in (400, 404):
            log.debug(
                "Skipping vertex ai endpoints in %s for %s (status=%s message=%s)",
                location, project, status or error_code, error_message)
            return True
        if error_code == 403 and error_message and 'disabled' in error_message:
            log.warning(error_message)
            return True
        if error_reason == 'accessNotConfigured':
            log.warning(
                "Resource:%s not available -> Service:%s not enabled on %s",
                self.type,
                self.resource_type.service,
                project)
            return True
        return False

    def _handle_locations_http_error(self, error, project):
        error_reason, error_code, error_message = extract_errors(error)
        status = getattr(error.resp, 'status', None)
        if error_code in (400, 404) or status in (400, 404):
            log.debug(
                "Skipping vertex ai locations for %s (status=%s message=%s)",
                project, status or error_code, error_message)
            return True
        if error_code == 403 and error_message and 'disabled' in error_message:
            log.warning(error_message)
            return True
        if error_reason == 'accessNotConfigured':
            log.warning(
                "Resource:%s not available -> Service:%s not enabled on %s",
                self.type,
                self.resource_type.service,
                project)
            return True
        return False
