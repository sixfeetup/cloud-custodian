from c7n.utils import local_session
from c7n.utils import type_schema
from c7n.exceptions import PolicyValidationError
from c7n_gcp.actions import MethodAction
from c7n_gcp.provider import resources
from c7n_gcp.query import RegionalResourceManager, ChildTypeInfo


@resources.register('artifact-repository')
class ArtifactRegistryRepository(RegionalResourceManager):
    """Artifact Registry Repository

    https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories
    """
    class resource_type(ChildTypeInfo):
        service = 'artifactregistry'
        version = 'v1'
        component = 'projects.locations.repositories'
        enum_spec = ('list', 'repositories[]', None)
        scope = 'parent'
        name = id = 'id'
        parent_spec = {
            'resource': 'region',
            'child_enum_params': {
                ('name', 'region')},
            'use_child_query': True,
        }
        permissions = ('artifactregistry.repositories.list',)
        default_report_fields = ['name', 'description', 'updateTime', 'sizeBytes']
        labels = True
        labels_op = 'patch'

        @staticmethod
        def get_label_params(resource, all_labels):
            return {
                'name': resource['name'],
                'body': {'labels': all_labels},
                'updateMask': 'labels'
            }

    def _get_child_enum_args(self, parent_instance):
        return {
            'parent': 'projects/{}/locations/{}'.format(
                local_session(self.session_factory).get_default_project(),
                parent_instance['name'],
            )
        }


@ArtifactRegistryRepository.action_registry.register('set-cleanup-policy')
class SetCleanupPolicy(MethodAction):
    """Set cleanup policy configuration for Artifact Registry repositories.

    Note:
      Artifact Registry expects `condition.olderThan` in protobuf Duration
      format (seconds with `s` suffix), for example `2592000s` for 30 days.

    :example:

    .. code-block:: yaml

      policies:
        - name: artifact-repository-cleanup-policy
          resource: gcp.artifact-repository
          filters:
            - type: value
              key: name
              value: projects/my-project/locations/us-central1/repositories/my-repo
          actions:
            - type: set-cleanup-policy
              cleanup-policies:
                delete-old:
                  id: delete-old
                  action: DELETE
                  condition:
                    olderThan: 2592000s
    """

    schema = type_schema(
        'set-cleanup-policy',
        **{
            'cleanup-policies': {'type': 'object'},
        })
    method_spec = {'op': 'patch'}
    method_perm = 'update'

    def validate(self):
        if 'cleanup-policies' not in self.data:
            raise PolicyValidationError(
                "policy:%s set-cleanup-policy requires cleanup-policies"
                % self.manager.ctx.policy.name)
        return self

    def get_resource_params(self, model, resource):
        body = {}
        update_mask = []

        if 'cleanup-policies' in self.data:
            body['cleanupPolicies'] = self.data['cleanup-policies']
            update_mask.append('cleanupPolicies')

        return {
            'name': resource['name'],
            'body': body,
            'updateMask': ','.join(update_mask)
        }
