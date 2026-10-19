# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import time
import typing

import botocore.client

import pytest
from pytest_terraform import terraform

from c7n.exceptions import PolicyValidationError
from c7n.resources.sagemaker import UpdateSagemakerUserProfile


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
                'UserSettings': {
                    app: {'DefaultResourceSpec': {'InstanceType': 'ml.t3.medium'}}
                    for app in apps
                },
            }],
        },
        session_factory=factory,
    )
    [resource] = policy.run()
    assert resource['UserProfileName'] == profile_name
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
        if profile['Status'] == 'InService':
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
            'actions': [{'type': 'update', 'UserSettings': settings}],
        },
        session_factory=factory,
    )
    [resource] = policy.run()
    assert resource['UserProfileName'] == profile_name
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
