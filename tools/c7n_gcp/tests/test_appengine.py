# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from gcp_common import BaseTest
from pytest_terraform import terraform


class AppEngineAppTest(BaseTest):

    def test_app_query(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        session_factory = self.replay_flight_data(
            'app-engine-query', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-dryrun',
             'resource': 'gcp.app-engine'},
            session_factory=session_factory)

        resources = policy.run()
        self.assertEqual(resources[0]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [f"gcp:appengine:europe-west3:{project_id}:app/{project_id}"],
        )

    def test_app_get(self):
        project_id = self.project_id
        app_name = 'apps/' + project_id
        session_factory = self.replay_flight_data(
            'app-engine-get', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-dryrun',
             'resource': 'gcp.app-engine'},
            session_factory=session_factory)

        resource = policy.resource_manager.get_resource(
            {'resourceName': app_name})
        self.assertEqual(resource['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns([resource]),
            [f"gcp:appengine:europe-west3:{project_id}:app/{project_id}"],
        )


class AppEngineCertificateTest(BaseTest):

    def test_certificate_query(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        certificate_id = '12277184'
        certificate_name = '{}/authorizedCertificates/{}'.format(app_name, certificate_id)
        session_factory = self.replay_flight_data(
            'app-engine-certificate-query', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-certificate-dryrun',
             'resource': 'gcp.app-engine-certificate'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resources = policy.run()
        self.assertEqual(resources[0]['name'], certificate_name)
        self.assertEqual(resources[0][parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [f"gcp:appengine:europe-west3:{project_id}:certificate/12277184"],
        )

    def test_certificate_get(self):
        project_id = self.project_id
        app_name = 'apps/' + project_id
        certificate_id = '12277184'
        certificate_name = '{}/authorizedCertificates/{}'.format(app_name, certificate_id)
        session_factory = self.replay_flight_data(
            'app-engine-certificate-get', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-certificate-dryrun',
             'resource': 'gcp.app-engine-certificate'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resource = policy.resource_manager.get_resource(
            {'resourceName': certificate_name})
        self.assertEqual(resource['name'], certificate_name)
        self.assertEqual(resource[parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns([resource]),
            [f"gcp:appengine:europe-west3:{project_id}:certificate/12277184"],
        )


class AppEngineDomainTest(BaseTest):

    def test_domain_query(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        domain_id = 'gcp-li.ga'
        domain_name = '{}/authorizedDomains/{}'.format(app_name, domain_id)
        session_factory = self.replay_flight_data(
            'app-engine-domain-query', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-domain-dryrun',
             'resource': 'gcp.app-engine-domain'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resources = policy.run()
        self.assertEqual(resources[0]['name'], domain_name)
        self.assertEqual(resources[0][parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [f"gcp:appengine:europe-west3:{project_id}:domain/gcp-li.ga"],
        )


class AppEngineDomainMappingTest(BaseTest):

    def test_domain_mapping_query(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        domain_mapping_id = 'alex.gcp-li.ga'
        domain_mapping_name = '{}/domainMappings/{}'.format(app_name, domain_mapping_id)
        session_factory = self.replay_flight_data(
            'app-engine-domain-mapping-query', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-domain-mapping-dryrun',
             'resource': 'gcp.app-engine-domain-mapping'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resources = policy.run()
        self.assertEqual(resources[0]['name'], domain_mapping_name)
        self.assertEqual(resources[0][parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [f"gcp:appengine:europe-west3:{project_id}:domain-mapping/alex.gcp-li.ga"],
        )

    def test_domain_mapping_get(self):
        project_id = self.project_id
        app_name = 'apps/' + project_id
        domain_mapping_id = 'alex.gcp-li.ga'
        domain_mapping_name = '{}/domainMappings/{}'.format(app_name, domain_mapping_id)
        session_factory = self.replay_flight_data(
            'app-engine-domain-mapping-get', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-domain-mapping-dryrun',
             'resource': 'gcp.app-engine-domain-mapping'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resource = policy.resource_manager.get_resource(
            {'resourceName': domain_mapping_name})
        self.assertEqual(resource['name'], domain_mapping_name)
        self.assertEqual(resource[parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns([resource]),
            [f"gcp:appengine:europe-west3:{project_id}:domain-mapping/alex.gcp-li.ga"],
        )


class AppEngineFirewallIngressRuleTest(BaseTest):

    def test_firewall_ingress_rule_query(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        rule_priority = 2147483647
        session_factory = self.replay_flight_data(
            'app-engine-firewall-ingress-rule-query', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-firewall-ingress-rule-dryrun',
             'resource': 'gcp.app-engine-firewall-ingress-rule'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resources = policy.run()
        self.assertEqual(resources[0]['priority'], rule_priority)
        self.assertEqual(resources[0][parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [f"gcp:appengine:europe-west3:{project_id}:firewall-ingress-rule/2147483647"],
        )

    def test_firewall_ingress_rule_get(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        rule_priority = 2147483647
        rule_priority_full = '{}/firewall/ingressRules/{}'.format(app_name, rule_priority)
        session_factory = self.replay_flight_data(
            'app-engine-firewall-ingress-rule-get', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-firewall-ingress-rule-dryrun',
             'resource': 'gcp.app-engine-firewall-ingress-rule'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resource = policy.resource_manager.get_resource(
            {'resourceName': rule_priority_full})
        self.assertEqual(resource['priority'], rule_priority)
        self.assertEqual(resource[parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns([resource]),
            [f"gcp:appengine:europe-west3:{project_id}:firewall-ingress-rule/2147483647"],
        )


class AppEngineServiceTest(BaseTest):

    def test_service_query(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        service_id = '12277184'
        service_name = '{}/services/{}'.format(app_name, service_id)
        session_factory = self.replay_flight_data(
            'app-engine-service-query', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-service-run',
             'resource': 'gcp.app-engine-service'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resources = policy.run()
        self.assertEqual(resources[0]['name'], service_name)
        self.assertEqual(resources[0][parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns(resources),
            [f"gcp:appengine:europe-west3:{project_id}:service/12277184"],
        )

    def test_service_get(self):
        project_id = self.project_id
        app_name = 'apps/' + project_id
        service_id = '12277184'
        service_name = '{}/services/{}'.format(app_name, service_id)
        session_factory = self.replay_flight_data(
            'app-engine-service-get', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-service-run',
             'resource': 'gcp.app-engine-service'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resource = policy.resource_manager.get_resource(
            {'resourceName': service_name})
        self.assertEqual(resource['name'], service_name)
        self.assertEqual(resource[parent_annotation_key]['name'], app_name)

        self.assertEqual(
            policy.resource_manager.get_urns([resource]),
            [f"gcp:appengine:europe-west3:{project_id}:service/12277184"],
        )


class AppEngineServiceVersionTest(BaseTest):

    def test_service_version(self):
        project_id = self.project_id
        app_name = 'apps/{}'.format(project_id)
        service_id = '12277184'
        version_id = 'v3'
        service_name = '{}/services/{}'.format(app_name, service_id)
        version = '{}/services/{}/versions/{}'.format(app_name, service_id, version_id)
        session_factory = self.replay_flight_data(
            'app-engine-service-version', project_id=project_id)

        policy = self.load_policy(
            {'name': 'gcp-app-engine-service-version-run',
             'resource': 'gcp.app-engine-service-version'},
            session_factory=session_factory)
        parent_annotation_key = policy.resource_manager.resource_type.get_parent_annotation_key()

        resources = policy.run()
        self.assertEqual(resources[0]['name'], version)
        self.assertEqual(resources[0][parent_annotation_key]['name'], service_name)


def _catch_all_security_levels(version):
    return [h['securityLevel'] for h in version['handlers'] if h['urlRegex'] == '/.*']


@terraform('app_engine_service_version', scope='session')
def test_app_engine_service_version_full_view(test, app_engine_service_version):
    always = app_engine_service_version[
        'google_app_engine_standard_app_version.secure_always.version_id']
    optional = app_engine_service_version[
        'google_app_engine_standard_app_version.secure_optional.version_id']
    factory = test.replay_flight_data('app_engine_service_version')
    policy = test.load_policy(
        {'name': 'app-engine-version-full-view',
         'resource': 'gcp.app-engine-service-version'},
        session_factory=factory)

    versions = {v['id']: v for v in policy.run()}

    assert _catch_all_security_levels(versions[always]) == ['SECURE_ALWAYS']
    assert _catch_all_security_levels(versions[optional]) == ['SECURE_OPTIONAL']


@terraform('app_engine_service_version', scope='session')
def test_app_engine_service_version_get(test, app_engine_service_version):
    name = app_engine_service_version[
        'google_app_engine_standard_app_version.secure_always.name']
    factory = test.replay_flight_data('app_engine_service_version_get')
    policy = test.load_policy(
        {'name': 'app-engine-version-get',
         'resource': 'gcp.app-engine-service-version'},
        session_factory=factory)

    version = policy.resource_manager.get_resource({'resourceName': name})

    assert version['name'] == name
    assert _catch_all_security_levels(version) == ['SECURE_ALWAYS']
    assert version['c7n:app-engine-service']['name'] == name.rsplit('/versions/', 1)[0]
