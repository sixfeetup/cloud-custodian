# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from azure.mgmt.resource.policy.models import PolicyAssignment
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.monitor import MonitorManagementClient

from c7n.actions import BaseAction
from c7n.exceptions import PolicyValidationError
from c7n.filters.missing import Missing
from c7n.filters.core import ValueFilter
from c7n.manager import ResourceManager
from c7n.utils import local_session, type_schema

from c7n_azure.actions.tagging import Tag, RemoveTag, TagTrim, TagDelayedAction
from c7n_azure.filters import TagActionFilter
from c7n_azure.provider import resources
from c7n_azure.query import QueryMeta, TypeInfo


@resources.register('subscription')
class Subscription(ResourceManager, metaclass=QueryMeta):
    """Subscription Resource

    :example:

    This policy creates Azure Policy scoped to the current subscription if doesn't exist.

    .. code-block:: yaml

        policies:
          - name: azure-policy-sample
            resource: azure.subscription
            filters:
              - type: missing
                policy:
                  resource: azure.policyassignments
                  filters:
                    - type: value
                      key: properties.displayName
                      op: eq
                      value_type: normalize
                      value: dn_sample_policy
            actions:
              - type: add-policy
                name: sample_policy
                display_name: dn_sample_policy
                definition_name: "Audit use of classic storage accounts"

    """

    class resource_type(TypeInfo):
        doc_groups = ['Subscription']

        id = 'subscriptionId'
        name = 'displayName'
        filter_name = None
        service = 'subscription'

    def get_model(self):
        return self.resource_type

    def get_session(self):
        """Get the session for this resource manager."""
        return local_session(self.session_factory)

    def resources(self):
        return self.filter_resources([self._get_subscription(self.session_factory, self.config)])

    def get_resources(self, resource_ids):
        return [self._get_subscription(self.session_factory, self.config)]

    def _get_subscription(self, session_factory, config):
        session = local_session(session_factory)
        client = SubscriptionClient(session.get_credentials())
        details = client.subscriptions.get(subscription_id=session.get_subscription_id())
        return details.serialize(True)

    def tag_operation_enabled(self, resource_type):
        """Subscriptions support tagging operations."""
        return True


Subscription.filter_registry.register('missing', Missing)

# Register tagging actions for subscriptions
Subscription.action_registry.register('tag', Tag)
Subscription.action_registry.register('untag', RemoveTag)
Subscription.action_registry.register('tag-trim', TagTrim)
Subscription.action_registry.register('mark-for-op', TagDelayedAction)
Subscription.filter_registry.register('marked-for-op', TagActionFilter)


@Subscription.filter_registry.register('diagnostic-settings')
class SubscriptionDiagnosticSettingFilter(ValueFilter):
    """Filter by diagnostic settings for this subscription

    Each diagnostic setting for the subscription is made available to the filter. The data format
    is the result of making the following Azure API call and extracting the "value" property:
    https://learn.microsoft.com/en-us/rest/api/monitor/subscription-diagnostic-settings/list?tabs=HTTP

    :example:

    Example JSON document showing the data format provided to the filter

    .. code-block:: json
        {
          "id": "...",
          "name": "...",
          "properties": {
            "eventHubAuthorizationRuleId": "...",
            "eventHubName": "...",
            "logs": [
              { "category": "Administrative", "enabled": true },
              { "category": "Security", "enabled": false }
            ],
            "marketplacePartnerId": "...",
            "serviceBusRuleId": "...",
            "storageAccountId": "...",
            "workspaceId": "..."
          },
          "systemData": {}
          "type": "..."
        }

    :example:

    Check if the subscription has Security logs enabled in at least one setting

    .. code-block:: yaml

        policies:
          - name: subscription-security-logs-enabled
            resource: azure.subscription
            filters:
              - not:
                - type: diagnostic-settings
                  key: "properties.logs[?category == 'Security'].enabled[]"
                  op: contains
                  value: true

    """

    cache_key = 'c7n:diagnostic-settings'

    schema = type_schema(
        'diagnostic-settings',
        rinherit=ValueFilter.schema
    )

    def _get_subscription_diagnostic_settings(self, session, subscription_id):
        client = MonitorManagementClient(
            session.get_credentials(),
            subscription_id=subscription_id
        )

        query = client.subscription_diagnostic_settings.list(subscription_id)

        settings = query.serialize(True).get('value', [])

        # put an empty item in when no diag settings so the absent operator can function
        if not settings:
            settings = [{}]

        return settings

    def process(self, resources, event=None):
        session = local_session(self.manager.session_factory)

        matched = []
        for resource in resources:
            subscription_id = resource['subscriptionId']

            if self.cache_key in resource:
                settings = resource[self.cache_key]
            else:
                settings = self._get_subscription_diagnostic_settings(
                    session,
                    subscription_id
                )
                resource[self.cache_key] = settings

            filtered_settings = super().process(settings, event=None)

            if filtered_settings:
                matched.append(resource)

        return matched


@Subscription.action_registry.register('add-policy')
class AddPolicy(BaseAction):

    schema = type_schema('add-policy',
        required=['name', 'display_name', 'definition_name'],
        scope={'type': 'string'},
        definition_name={'type': 'string'},
        name={'type': 'string'},
        display_name={'type': 'string'})

    policyDefinitionPrefix = '/providers/Microsoft.Authorization/policyDefinitions/'

    def __init__(self, data=None, manager=None, log_dir=None):
        super(AddPolicy, self).__init__(data, manager, log_dir)

        self.paName = self.data.get('name')
        self.displayName = self.data.get('display_name')

        self.policyDefinitionName = self.data['definition_name']

    def _get_definition_id(self, name):
        return next((r for r in self.policyClient.policy_definitions.list()
                     if name == r.display_name or name == r.id or name == r.name), None)

    def _add_policy(self, subscription):
        parameters = PolicyAssignment(
            display_name=self.displayName,
            policy_definition_id=self.policyDefinition.id)
        self.policyClient.policy_assignments.create(
            scope=self.scope,
            policy_assignment_name=self.paName,
            parameters=parameters
        )

    def process(self, subscriptions):
        self.session = local_session(self.manager.session_factory)
        self.policyClient = self.session.client("azure.mgmt.resource.policy.PolicyClient")

        self.scope = '/subscriptions/' + self.session.subscription_id + \
                     '/' + self.data.get('scope', '')
        self.policyDefinition = self._get_definition_id(self.policyDefinitionName)
        if self.policyDefinition is None:
            raise PolicyValidationError(
                "Azure Policy Definition '%s' not found." % (
                    self.policyDefinitionName))

        for s in subscriptions:
            self._add_policy(s)


@Subscription.action_registry.register('set-activity-log-alert')
class SetActivityLogAlert(BaseAction):
    """Create or update an activity log alert on the subscription.

    The alert watches the subscription's activity log and fires when an event
    matches every entry in ``conditions``. It is written by ``name``, so running
    the action again updates the existing alert rather than adding a second one.

    - ``name``: the alert's name.
    - ``resource_group``: the resource group to create the alert in. It must
      already exist.
    - ``conditions``: a list of ``field`` and ``equals`` pairs. An event must
      match all of them to fire the alert.
    - ``action_groups``: optional list of action group IDs to notify. Defaults
      to none.
    - ``description``: optional description for the alert.
    - ``enabled``: optional, defaults to ``true``.

    :example:

    Create an alert for network security group writes on any subscription that
    doesn't have one:

    .. code-block:: yaml

        policies:
          - name: azure-subscription-nsg-write-alert
            resource: azure.subscription
            filters:
              - type: missing
                policy:
                  resource: azure.alert-logs
                  filters:
                    - type: value
                      key: properties.condition.allOf[].equals | sort(@)
                      op: eq
                      value:
                        - Administrative
                        - Microsoft.Network/networkSecurityGroups/write
            actions:
              - type: set-activity-log-alert
                name: nsg-write-alert
                resource_group: my-alerts-rg
                conditions:
                  - field: category
                    equals: Administrative
                  - field: operationName
                    equals: Microsoft.Network/networkSecurityGroups/write
    """

    schema = type_schema(
        'set-activity-log-alert',
        required=['name', 'resource_group', 'conditions'],
        name={'type': 'string', 'minLength': 1},
        resource_group={'type': 'string', 'minLength': 1},
        conditions={
            'type': 'array',
            'minItems': 1,
            'items': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['field', 'equals'],
                'properties': {
                    'field': {'type': 'string'},
                    'equals': {'type': 'string'},
                },
            },
        },
        action_groups={'type': 'array', 'items': {'type': 'string'}},
        description={'type': 'string'},
        enabled={'type': 'boolean'},
    )

    def alert_body(self, subscription):
        """Return the request body that creates the alert on ``subscription``."""
        body = {
            'location': 'Global',
            'scopes': [subscription['id']],
            'condition': {'allOf': self.data['conditions']},
            'actions': {'actionGroups': [
                {'actionGroupId': group_id}
                for group_id in self.data.get('action_groups', [])
            ]},
            'enabled': self.data.get('enabled', True),
        }
        if 'description' in self.data:
            body['description'] = self.data['description']
        return body

    def process(self, subscriptions):
        client = self.manager.get_session().client(
            'azure.mgmt.monitor.MonitorManagementClient')

        for s in subscriptions:
            # Positional on purpose: azure-mgmt-monitor 7.0 renamed the third
            # parameter, so naming it would break on either 2.0 or 7.0.
            client.activity_log_alerts.create_or_update(
                self.data['resource_group'], self.data['name'], self.alert_body(s))
