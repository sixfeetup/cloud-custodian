# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import copy
import time
import typing

import botocore.client

import pytest
from pytest_terraform import terraform

from c7n.exceptions import PolicyValidationError
from c7n.resources.sagemaker import UpdateSagemakerUserProfile

from .apicallcaptor import ApiCallCaptor


def test_sagemaker_user_profile_update_validate():
    action = UpdateSagemakerUserProfile({
        'type': 'update',
        'UserSettings': {
            'KernelGatewayAppSettings': {
                'DefaultResourceSpec': {'InstanceType': 'ml.t3.medium'},
            },
        },
    })
    action.validate()

    action.data['UserSettings'] = {'CustomPosixUserConfig': {'Uid': 10000, 'Gid': 1001}}
    with pytest.raises(PolicyValidationError):
        action.validate()


@pytest.mark.audited
@terraform('sagemaker_user_profile_update', scope='module')
def test_sagemaker_user_profile_update(test, sagemaker_user_profile_update):
    factory = test.replay_flight_data('test_sagemaker_user_profile_update')
    client = factory().client('sagemaker')
    domain_id = sagemaker_user_profile_update['aws_sagemaker_domain.main.id']
    profile_name = sagemaker_user_profile_update[
        'aws_sagemaker_user_profile.main.user_profile_name']
    apps = (
        'KernelGatewayAppSettings',
        'JupyterLabAppSettings',
        'CodeEditorAppSettings',
    )
    before = client.describe_user_profile(
        DomainId=domain_id,
        UserProfileName=profile_name,
    )['UserSettings']
    for app in apps:
        assert before[app]['DefaultResourceSpec']['InstanceType'] == 'ml.g4dn.xlarge'
    user_settings = {
        app: {'DefaultResourceSpec': {'InstanceType': 'ml.t3.medium'}}
        for app in apps
    }
    policy = test.load_policy(
        {
            'name': 'sagemaker-user-profile-cpu-default',
            'resource': 'aws.sagemaker-user-profile',
            'filters': [
                {'DomainId': domain_id},
                {'UserProfileName': profile_name},
                {
                    'type': 'value',
                    'key': ('UserSettings.KernelGatewayAppSettings.'
                            'DefaultResourceSpec.InstanceType'),
                    'op': 'regex',
                    'value': '^ml[.](g|p)[a-z0-9.]+$',
                },
            ],
            'actions': [{
                'type': 'update',
                'UserSettings': copy.deepcopy(user_settings),
            }],
        },
        session_factory=factory,
    )
    captor = ApiCallCaptor.start_capture()
    [resource] = policy.run()
    assert resource['UserProfileName'] == profile_name
    assert [
        call['params'] for call in captor.calls
        if call.get('operation') == 'UpdateUserProfile'
    ] == [{
        'DomainId': domain_id,
        'UserProfileName': profile_name,
        'UserSettings': user_settings,
    }]
    for _ in range(60):
        updated = client.describe_user_profile(
            DomainId=domain_id,
            UserProfileName=profile_name,
        )
        if updated['Status'] == 'InService':
            break
        if test.recording:
            time.sleep(5)
    assert updated['Status'] == 'InService'
    settings = updated['UserSettings']
    for app in apps:
        assert settings[app]['DefaultResourceSpec']['InstanceType'] == 'ml.t3.medium'
    assert settings['ExecutionRole'] == before['ExecutionRole']
    assert settings['JupyterLabAppSettings']['CodeRepositories'] == [{
        'RepositoryUrl': 'https://github.com/cloud-custodian/cloud-custodian',
    }]


def describe_user_profile(
    test: typing.Any,
    client: botocore.client.BaseClient,
    domain_id: str,
    profile_name: str,
) -> dict:
    for _ in range(60):
        profile = client.describe_user_profile(
            DomainId=domain_id,
            UserProfileName=profile_name,
        )
        status = profile['Status']
        assert status in ('Pending', 'Updating', 'InService'), profile.get('FailureReason')
        if status == 'InService':
            break
        if test.recording:
            time.sleep(5)
    assert profile['Status'] == 'InService'
    return profile


def update_user_profile(
    test: typing.Any,
    factory: typing.Callable,
    domain_id: str,
    profile_name: str,
    settings: dict,
) -> dict:
    policy = test.load_policy(
        {
            'name': 'update-user-profile-settings',
            'resource': 'aws.sagemaker-user-profile',
            'filters': [
                {'DomainId': domain_id},
                {'UserProfileName': profile_name},
            ],
            'actions': [{'type': 'update', 'UserSettings': copy.deepcopy(settings)}],
        },
        session_factory=factory,
    )
    captor = ApiCallCaptor.start_capture()
    [resource] = policy.run()
    assert resource['UserProfileName'] == profile_name
    assert [
        call['params'] for call in captor.calls
        if call.get('operation') == 'UpdateUserProfile'
    ] == [{
        'DomainId': domain_id,
        'UserProfileName': profile_name,
        'UserSettings': settings,
    }]
    return describe_user_profile(
        test,
        factory().client('sagemaker'),
        domain_id,
        profile_name,
    )['UserSettings']


@pytest.mark.audited
@terraform('sagemaker_user_profile_update', scope='module')
def test_sagemaker_user_profile_update_settings(test, sagemaker_user_profile_update):
    fixture = sagemaker_user_profile_update
    factory = test.replay_flight_data('test_sagemaker_user_profile_update_settings')
    client = factory().client('sagemaker')
    domain_id = fixture['aws_sagemaker_domain.main.id']
    profile_name = fixture['aws_sagemaker_user_profile.settings.user_profile_name']
    before = describe_user_profile(test, client, domain_id, profile_name)['UserSettings']
    assert before['ExecutionRole'] == fixture['aws_iam_role.execution.arn']
    assert fixture['aws_security_group.initial.id'] in before['SecurityGroups']
    sharing = {
        'NotebookOutputOption': 'Allowed',
        'S3OutputPath': f"s3://{fixture['aws_s3_bucket.sharing.bucket']}/notebooks/",
        'S3KmsKeyId': fixture['aws_kms_key.sharing.arn'],
    }
    storage = {
        'DefaultEbsStorageSettings': {
            'DefaultEbsVolumeSizeInGb': 10,
            'MaximumEbsVolumeSizeInGb': 30,
        },
    }
    portal = {
        'HiddenMlTools': ['DataWrangler'],
        'HiddenAppTypes': ['TensorBoard'],
        'HiddenInstanceTypes': ['ml.g4dn.xlarge'],
        'HiddenSageMakerImageVersionAliases': [{
            'SageMakerImageName': 'sagemaker_distribution',
            'VersionAliases': ['2.0'],
        }],
        'ExecutionRoleSessionNameMode': 'USER_IDENTITY',
    }
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {
            'ExecutionRole': fixture['aws_iam_role.updated_execution.arn'],
            'SecurityGroups': [fixture['aws_security_group.updated.id']],
            'SharingSettings': sharing,
            'DefaultLandingUri': 'studio::',
            'StudioWebPortal': 'ENABLED',
            'SpaceStorageSettings': storage,
            'AutoMountHomeEFS': 'Disabled',
            'StudioWebPortalSettings': portal,
        },
    )
    assert updated['ExecutionRole'] == fixture['aws_iam_role.updated_execution.arn']
    assert fixture['aws_security_group.updated.id'] in updated['SecurityGroups']
    assert fixture['aws_security_group.initial.id'] not in updated['SecurityGroups']
    assert updated['SharingSettings'] == sharing
    assert updated['DefaultLandingUri'] == 'studio::'
    assert updated['StudioWebPortal'] == 'ENABLED'
    assert updated['SpaceStorageSettings'] == storage
    assert updated['AutoMountHomeEFS'] == 'Disabled'
    assert updated['StudioWebPortalSettings'] == portal

    cleared = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {
            'StudioWebPortal': 'DISABLED',
            'DefaultLandingUri': 'app:JupyterServer:',
            'AutoMountHomeEFS': 'Enabled',
            'SharingSettings': {'NotebookOutputOption': 'Disabled'},
            'StudioWebPortalSettings': {
                'HiddenMlTools': [],
                'HiddenAppTypes': [],
                'HiddenInstanceTypes': [],
                'HiddenSageMakerImageVersionAliases': [],
                'ExecutionRoleSessionNameMode': 'STATIC',
            },
        },
    )
    assert cleared['StudioWebPortal'] == 'DISABLED'
    assert cleared['DefaultLandingUri'] == 'app:JupyterServer:'
    assert cleared['AutoMountHomeEFS'] == 'Enabled'
    assert cleared['SharingSettings']['NotebookOutputOption'] == 'Disabled'
    assert cleared['StudioWebPortalSettings'] == {
        'HiddenMlTools': [],
        'HiddenAppTypes': [],
        'HiddenInstanceTypes': [],
        'HiddenSageMakerImageVersionAliases': [],
        'ExecutionRoleSessionNameMode': 'STATIC',
    }


@pytest.mark.audited
@terraform('sagemaker_user_profile_update', scope='module')
def test_sagemaker_user_profile_update_rstudio(test, sagemaker_user_profile_update):
    fixture = sagemaker_user_profile_update
    factory = test.replay_flight_data('test_sagemaker_user_profile_update_rstudio')
    domain_id = fixture['aws_sagemaker_domain.main.id']
    profile_name = fixture['aws_sagemaker_user_profile.rstudio.user_profile_name']
    before = describe_user_profile(
        test,
        factory().client('sagemaker'),
        domain_id,
        profile_name,
    )['UserSettings']
    assert before['RStudioServerProAppSettings']['AccessStatus'] == 'DISABLED'
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {
            'RStudioServerProAppSettings': {
                'AccessStatus': 'ENABLED',
                'UserGroup': 'R_STUDIO_ADMIN',
            },
        },
    )
    assert updated['RStudioServerProAppSettings'] == {
        'AccessStatus': 'ENABLED',
        'UserGroup': 'R_STUDIO_ADMIN',
    }


@pytest.mark.audited
@terraform('sagemaker_user_profile_update', scope='module')
def test_sagemaker_user_profile_update_canvas_settings(
    test,
    sagemaker_user_profile_update,
):
    fixture = sagemaker_user_profile_update
    factory = test.replay_flight_data('test_sagemaker_user_profile_update_canvas_settings')
    domain_id = fixture['aws_sagemaker_domain.main.id']
    profile_name = fixture['aws_sagemaker_user_profile.canvas.user_profile_name']
    canvas = {
        'TimeSeriesForecastingSettings': {
            'Status': 'ENABLED',
            'AmazonForecastRoleArn': fixture['aws_iam_role.canvas.arn'],
        },
        'ModelRegisterSettings': {
            'Status': 'ENABLED',
            'CrossAccountModelRegisterRoleArn': fixture['aws_iam_role.canvas.arn'],
        },
        'WorkspaceSettings': {
            'S3ArtifactPath': f"s3://{fixture['aws_s3_bucket.sharing.bucket']}/canvas/",
            'S3KmsKeyId': fixture['aws_kms_key.sharing.arn'],
        },
        'IdentityProviderOAuthSettings': [{
            'DataSourceName': 'Snowflake',
            'Status': 'ENABLED',
            'SecretArn': fixture['aws_secretsmanager_secret.oauth.arn'],
        }],
        'DirectDeploySettings': {'Status': 'ENABLED'},
        'KendraSettings': {'Status': 'ENABLED'},
        'GenerativeAiSettings': {
            'AmazonBedrockRoleArn': fixture['aws_iam_role.canvas.arn'],
        },
        'EmrServerlessSettings': {
            'Status': 'ENABLED',
            'ExecutionRoleArn': fixture['aws_iam_role.canvas.arn'],
        },
    }
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {'CanvasAppSettings': canvas},
    )
    assert updated['CanvasAppSettings'] == canvas
    disabled = {
        'TimeSeriesForecastingSettings': {'Status': 'DISABLED'},
        'ModelRegisterSettings': {'Status': 'DISABLED'},
        'DirectDeploySettings': {'Status': 'DISABLED'},
        'KendraSettings': {'Status': 'DISABLED'},
        'EmrServerlessSettings': {'Status': 'DISABLED'},
        'IdentityProviderOAuthSettings': [],
    }
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {'CanvasAppSettings': disabled},
    )
    for app, settings in disabled.items():
        if app == 'IdentityProviderOAuthSettings':
            assert updated['CanvasAppSettings'][app] == []
        else:
            assert updated['CanvasAppSettings'][app]['Status'] == settings['Status']


def assert_settings(actual: dict, expected: dict) -> None:
    for name, value in expected.items():
        if isinstance(value, dict):
            assert_settings(actual[name], value)
        else:
            assert actual[name] == value, name


@pytest.mark.audited
@terraform('sagemaker_user_profile_update', scope='module')
def test_sagemaker_user_profile_update_app_settings(test, sagemaker_user_profile_update):
    fixture = sagemaker_user_profile_update
    factory = test.replay_flight_data('test_sagemaker_user_profile_update_app_settings')
    domain_id = fixture['aws_sagemaker_domain.main.id']
    profile_name = fixture['aws_sagemaker_user_profile.app.user_profile_name']
    lifecycle_configs = fixture.outputs['lifecycle_configs']['value']
    apps = {
        'JupyterServerAppSettings': 'JupyterServer',
        'KernelGatewayAppSettings': 'KernelGateway',
        'TensorBoardAppSettings': 'TensorBoard',
        'RSessionAppSettings': 'RSessionGateway',
        'CodeEditorAppSettings': 'CodeEditor',
        'JupyterLabAppSettings': 'JupyterLab',
    }
    settings = {}
    clear = {}
    for app, app_type in apps.items():
        instance_type = 'system' if app_type == 'JupyterServer' else 'ml.t3.medium'
        image_arn = fixture['aws_sagemaker_image.app.arn']
        if app_type == 'JupyterServer':
            image_arn = fixture.outputs['jupyter_server_image']['value']
        spec = {'SageMakerImageArn': image_arn, 'InstanceType': instance_type}
        app_settings = {'DefaultResourceSpec': spec}
        app_clear = {}
        if app in lifecycle_configs:
            lifecycle = lifecycle_configs[app]
            spec['LifecycleConfigArn'] = lifecycle['default']
            app_settings['LifecycleConfigArns'] = [lifecycle['default']]
            app_clear['LifecycleConfigArns'] = []
            app_clear['DefaultResourceSpec'] = {'InstanceType': instance_type}
            if app_type != 'JupyterServer':
                app_clear['DefaultResourceSpec']['LifecycleConfigArn'] = 'None'
        if app_type in ('KernelGateway', 'RSessionGateway', 'CodeEditor', 'JupyterLab'):
            app_settings['CustomImages'] = [{
                'ImageName': fixture['aws_sagemaker_image.app.image_name'],
                'ImageVersionNumber': fixture['aws_sagemaker_image_version.updated.version'],
                'AppImageConfigName': fixture.outputs['app_image_configs']['value'][app_type],
            }]
            app_clear['CustomImages'] = []
        if app_type in ('JupyterServer', 'JupyterLab'):
            app_settings['CodeRepositories'] = [{
                'RepositoryUrl': 'https://github.com/cloud-custodian/cloud-custodian',
            }]
            app_clear['CodeRepositories'] = []
        if app_type in ('JupyterLab', 'CodeEditor'):
            app_settings['BuiltInLifecycleConfigArn'] = lifecycle_configs[app]['builtin']
            app_settings['AppLifecycleManagement'] = {'IdleSettings': {
                'LifecycleManagement': 'ENABLED',
                'IdleTimeoutInMinutes': 120,
                'MinIdleTimeoutInMinutes': 60,
                'MaxIdleTimeoutInMinutes': 240,
            }}
            app_clear['AppLifecycleManagement'] = {'IdleSettings': {
                'LifecycleManagement': 'DISABLED',
            }}
        if app_type == 'JupyterLab':
            app_settings['EmrSettings'] = {
                'AssumableRoleArns': [fixture['aws_iam_role.emr_assumable.arn']],
                'ExecutionRoleArns': [fixture['aws_iam_role.canvas.arn']],
            }
            app_clear['EmrSettings'] = {'AssumableRoleArns': [], 'ExecutionRoleArns': []}
        settings[app] = app_settings
        if app_clear:
            clear[app] = app_clear

    updated = update_user_profile(test, factory, domain_id, profile_name, settings)
    assert_settings(updated, settings)
    assert updated['ExecutionRole'] == fixture['aws_iam_role.execution.arn']

    versioned_apps = (
        'KernelGatewayAppSettings',
        'TensorBoardAppSettings',
        'RSessionAppSettings',
        'CodeEditorAppSettings',
        'JupyterLabAppSettings',
    )
    initial_version = fixture['aws_sagemaker_image_version.initial.arn']
    versions = {
        app: {'DefaultResourceSpec': {'SageMakerImageVersionArn': initial_version}}
        for app in versioned_apps
    }
    updated = update_user_profile(test, factory, domain_id, profile_name, versions)
    assert_settings(updated, versions)
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {
            app: {'DefaultResourceSpec': {'SageMakerImageVersionArn': 'None'}}
            for app in versioned_apps
        },
    )
    for app in versioned_apps:
        assert updated[app]['DefaultResourceSpec'].get('SageMakerImageVersionArn') in (
            None,
            'None',
        )
    aliases = {
        app: {'DefaultResourceSpec': {
            'SageMakerImageVersionAlias': '1' if app_type == 'JupyterServer' else '2.0.0',
        }}
        for app, app_type in apps.items()
    }
    aliases['JupyterServerAppSettings']['DefaultResourceSpec']['LifecycleConfigArn'] = (
        lifecycle_configs['JupyterServerAppSettings']['default']
    )
    updated = update_user_profile(test, factory, domain_id, profile_name, aliases)
    assert_settings(updated, aliases)
    updated = update_user_profile(test, factory, domain_id, profile_name, clear)
    for app, app_clear in clear.items():
        for field, value in app_clear.items():
            if field == 'DefaultResourceSpec':
                assert updated[app][field].get('LifecycleConfigArn') in (None, 'None')
            else:
                assert_settings(updated[app], {field: value})
