# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import datetime
import re
from urllib.parse import urlsplit, urlunsplit

import requests

from c7n.exceptions import PolicyValidationError
from c7n.filters.core import Filter, type_schema
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ChildArmResourceManager


WORKSPACE_DISCOVERY_URL = 'c7n:WorkspaceDiscoveryUrl'
DURATION_UNITS = {
    'm': 'minutes',
    'h': 'hours',
    'd': 'days',
    'w': 'weeks',
}
NONTERMINAL_STATUSES = (
    'NotStarted',
    'Starting',
    'Provisioning',
    'Preparing',
    'Queued',
    'Running',
    'Finalizing',
    'CancelRequested',
    'NotResponding',
)


@resources.register('machine-learning-compute-cluster')
class MachineLearningComputeCluster(ChildArmResourceManager):

    class resource_type(ChildArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']
        service = 'azure.mgmt.machinelearningservices'
        client = 'MachineLearningServicesMgmtClient'
        enum_spec = ('compute', 'list', None)
        parent_manager_name = 'machine-learning-workspace'
        resource_type = 'Microsoft.MachineLearningServices/workspaces/computes'
        default_report_fields = (
            'name',
            'resourceGroup',
            '"c7n:parent-id"',
            'properties.properties.currentNodeCount',
            'properties.properties.nodeStateCounts.runningNodeCount',
            'properties.properties.scaleSettings.minNodeCount',
            'properties.properties.scaleSettings.maxNodeCount',
        )

        @classmethod
        def extra_args(cls, parent_resource):
            return {
                'resource_group_name': parent_resource['resourceGroup'],
                'workspace_name': parent_resource['name'],
            }

    def enumerate_resources(self, parent_resource, type_info, vault_url=None, **params):
        resources = super().enumerate_resources(
            parent_resource,
            type_info,
            vault_url=vault_url,
            **params,
        )
        clusters = [
            resource for resource in resources
            if resource['properties']['computeType'] == 'AmlCompute'
        ]
        for cluster in clusters:
            cluster[WORKSPACE_DISCOVERY_URL] = (
                parent_resource['properties']['discoveryUrl']
            )
        return clusters


@MachineLearningComputeCluster.filter_registry.register('inactive')
class InactiveFilter(Filter):
    schema = type_schema(
        'inactive',
        required=['since'],
        since={
            'type': 'string',
            'pattern': r'^[1-9][0-9]*[mhdw]$',
        },
    )

    def validate(self):
        if 'since' not in self.data:
            raise PolicyValidationError("inactive filter requires 'since'")
        return self

    def process(
        self,
        resources: list[dict],
        event=None,
    ) -> list[dict]:
        match = re.fullmatch(r'([1-9][0-9]*)([mhdw])', self.data['since'])
        amount, unit = match.groups()
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            **{DURATION_UNITS[unit]: int(amount)}
        )

        unresolved = []
        workspaces = {}
        for resource in resources:
            running_nodes = resource['properties']['properties'][
                'nodeStateCounts'
            ]['runningNodeCount']
            if running_nodes > 0:
                continue
            unresolved.append(resource)
            workspaces.setdefault(resource['c7n:parent-id'], []).append(resource)

        active_targets = {}
        for workspace_id, workspace_resources in workspaces.items():
            active_targets[workspace_id] = self._get_active_targets(
                workspace_resources,
                cutoff,
            )

        return [
            resource for resource in unresolved
            if resource['name'].lower()
            not in active_targets[resource['c7n:parent-id']]
        ]

    def _query_history(self, url: str, body: dict) -> list[dict]:
        session = self.manager.get_session()
        session._initialize_session()
        token = session.credentials.get_token('https://ml.azure.com/.default')
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json',
        }
        params = {'api-version': '2023-10-01'}
        values = []
        request_body = dict(body)

        while True:
            response = requests.post(
                url,
                headers=headers,
                params=params,
                json=request_body,
                timeout=30,
            )
            response.raise_for_status()
            page = response.json()
            if not isinstance(page, dict) or not isinstance(page.get('value'), list):
                raise TypeError('Run History response value must be a list')
            values.extend(page['value'])
            continuation_token = page.get('continuationToken')
            if not continuation_token:
                return values
            request_body = dict(body)
            request_body['continuationToken'] = continuation_token

    def _get_experiments(
        self,
        workspace: dict,
        cutoff: datetime.datetime,
    ) -> list[str]:
        endpoint = self._get_history_endpoint(workspace)
        workspace_id = workspace['c7n:parent-id']
        url = f'{endpoint}/history/v1.0{workspace_id}/experiments:query'
        cutoff_text = self._format_cutoff(cutoff)
        experiments = self._query_history(url, {'viewType': 'ActiveOnly'})
        experiments.extend(self._query_history(
            url,
            {
                'viewType': 'ArchivedOnly',
                'filter': f'archivedTime ge {cutoff_text}',
            },
        ))

        experiment_ids = []
        seen = set()
        for experiment in experiments:
            experiment_id = experiment.get('experimentId')
            if experiment_id and experiment_id not in seen:
                experiment_ids.append(experiment_id)
                seen.add(experiment_id)
        return experiment_ids

    def _get_active_targets(
        self,
        resources: list[dict],
        cutoff: datetime.datetime,
    ) -> set[str]:
        workspace = resources[0]
        endpoint = self._get_history_endpoint(workspace)
        workspace_id = workspace['c7n:parent-id']
        cutoff_text = self._format_cutoff(cutoff)
        status_filter = ' or '.join(
            f"status eq '{status}'" for status in NONTERMINAL_STATUSES
        )
        targets = set()

        for experiment_id in self._get_experiments(workspace, cutoff):
            url = (
                f'{endpoint}/history/v1.0{workspace_id}/experimentids/'
                f'{experiment_id}/runs:query'
            )
            runs = self._query_history(url, {'filter': status_filter})
            runs.extend(self._query_history(
                url,
                {'filter': f'endTimeUtc ge {cutoff_text}'},
            ))
            for run in runs:
                target = run.get('target')
                if isinstance(target, str) and target:
                    targets.add(target.lower())
        return targets

    @staticmethod
    def _get_history_endpoint(workspace: dict) -> str:
        discovery_url = workspace[WORKSPACE_DISCOVERY_URL]
        parts = urlsplit(discovery_url)
        if not parts.path.endswith('/discovery'):
            raise ValueError('Workspace discovery URL must end in /discovery')
        path = parts.path[:-len('/discovery')]
        return urlunsplit((parts.scheme, parts.netloc, path, '', ''))

    @staticmethod
    def _format_cutoff(cutoff: datetime.datetime) -> str:
        return cutoff.astimezone(datetime.timezone.utc).isoformat().replace(
            '+00:00',
            'Z',
        )
