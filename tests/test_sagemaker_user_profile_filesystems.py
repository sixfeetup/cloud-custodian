# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import pytest
from pytest_terraform import terraform

from .test_sagemaker_user_profile import (
    assert_settings,
    describe_user_profile,
    update_user_profile,
)


@pytest.mark.audited
@terraform('sagemaker_user_profile_filesystems')
def test_sagemaker_user_profile_update_filesystems(
    test,
    sagemaker_user_profile_filesystems,
):
    fixture = sagemaker_user_profile_filesystems
    factory = test.replay_flight_data('test_sagemaker_user_profile_update_filesystems')
    domain_id = fixture['aws_sagemaker_domain.main.id']
    profile_name = fixture['aws_sagemaker_user_profile.main.user_profile_name']
    before = describe_user_profile(
        test,
        factory().client('sagemaker'),
        domain_id,
        profile_name,
    )['UserSettings']
    assert not before.get('CustomFileSystemConfigs')
    configs = [
        {'EFSFileSystemConfig': {
            'FileSystemId': fixture['aws_efs_file_system.custom.id'],
            'FileSystemPath': '/c7n-recording',
        }},
        {'FSxLustreFileSystemConfig': {
            'FileSystemId': fixture['aws_fsx_lustre_file_system.custom.id'],
            'FileSystemPath': '/c7n-recording',
        }},
    ]
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {'CustomFileSystemConfigs': configs},
    )
    actual = updated['CustomFileSystemConfigs']
    assert len(actual) == len(configs)
    for expected in configs:
        kind = next(iter(expected))
        [matching] = [item for item in actual if kind in item]
        assert_settings(matching, expected)

    replacement = [{'EFSFileSystemConfig': {
        'FileSystemId': fixture['aws_efs_file_system.custom.id'],
        'FileSystemPath': '/c7n-updated',
    }}]
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {'CustomFileSystemConfigs': replacement},
    )
    assert updated['CustomFileSystemConfigs'] == replacement
    updated = update_user_profile(
        test,
        factory,
        domain_id,
        profile_name,
        {'CustomFileSystemConfigs': []},
    )
    assert not updated.get('CustomFileSystemConfigs')
