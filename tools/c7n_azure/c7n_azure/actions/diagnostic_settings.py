# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from azure.mgmt.resource.resources.models import GenericResource
from c7n_azure.actions.base import AzureBaseAction
from c7n_azure.filters import DiagnosticSettingsFilter

from c7n.exceptions import PolicyValidationError
from c7n.utils import type_schema


class SetDiagnosticSettingsAction(AzureBaseAction):
    """
    Create or update an Azure Monitor diagnostic setting on a resource.

    The setting called ``name`` is written whole, so an existing setting with
    that name is replaced. Other settings on the resource are left alone.

    The caller needs ``Microsoft.Insights/diagnosticSettings/write`` on the
    resource. Storage account and Event Hub destinations also need permission
    to list their keys.

    :example:

    Send HTTP logs to a Log Analytics workspace for web apps that don't
    already send them anywhere:

    .. code-block:: yaml

       policies:
         - name: webapp-enable-http-logs
           resource: azure.webapp
           filters:
             - not:
               - type: diagnostic-settings
                 key: 'logs[?category==`AppServiceHTTPLogs` && enabled]'
                 value: not-null
           actions:
             - type: set-diagnostic-settings
               name: c7n-http-logs
               workspaceId: >-
                 /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/logging-rg/providers/Microsoft.OperationalInsights/workspaces/security-logs
               logs:
                 - category: AppServiceHTTPLogs
                   enabled: true
    """

    schema = type_schema(
        'set-diagnostic-settings',
        required=['name'],
        name={'type': 'string'},
        workspaceId={'type': 'string'},
        storageAccountId={'type': 'string'},
        eventHubAuthorizationRuleId={'type': 'string'},
        eventHubName={'type': 'string'},
        logs={
            'type': 'array',
            'items': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['enabled'],
                'properties': {
                    'category': {'type': 'string'},
                    'categoryGroup': {'type': 'string'},
                    'enabled': {'type': 'boolean'},
                },
            },
        },
        metrics={
            'type': 'array',
            'items': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['enabled'],
                'properties': {
                    'category': {'type': 'string'},
                    'enabled': {'type': 'boolean'},
                },
            },
        },
    )
    schema_alias = True

    # Policy fields that are sent to Azure unchanged as the setting's properties
    PROPERTIES = ('workspaceId', 'storageAccountId', 'eventHubAuthorizationRuleId',
                  'eventHubName', 'logs', 'metrics')

    def validate(self):
        destinations = ('workspaceId', 'storageAccountId', 'eventHubAuthorizationRuleId')
        if not any(self.data.get(d) for d in destinations):
            raise PolicyValidationError(
                "set-diagnostic-settings needs a destination: "
                "workspaceId, storageAccountId or eventHubAuthorizationRuleId"
            )

        if not self.data.get('logs') and not self.data.get('metrics'):
            raise PolicyValidationError(
                "set-diagnostic-settings needs logs or metrics to send"
            )

        for entry in self.data.get('logs', []):
            if ('category' in entry) == ('categoryGroup' in entry):
                raise PolicyValidationError(
                    "set-diagnostic-settings: each logs entry needs exactly one of "
                    "category or categoryGroup, got {}".format(entry)
                )

        return self

    def _prepare_processing(self):
        self.client = self.manager.get_client('azure.mgmt.resource.ResourceManagementClient')

    def _process_resource(self, resource):
        setting_id = '{}/providers/Microsoft.Insights/diagnosticSettings/{}'.format(
            resource['id'], self.data['name'])
        body = {k: self.data[k] for k in self.PROPERTIES if k in self.data}

        # The monitor SDK's diagnostic_settings can't send categoryGroup, so
        # write the setting as a generic resource at the filter's api-version.
        self.client.resources.begin_create_or_update_by_id(
            setting_id,
            DiagnosticSettingsFilter.api_version,
            GenericResource(properties=body),
        ).result()

        return "Set diagnostic setting '{}'".format(self.data['name'])
