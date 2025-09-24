# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter, strip_output_path, _get_values
from .common import BaseTest, load_data


class TestEC2Report(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["ec2"]["records"]
        self.headers = data["ec2"]["headers"]
        self.rows = data["ec2"]["rows"]
        self.p = self.load_policy({"name": "report-test-ec2", "resource": "ec2"})

    def test_default_csv(self):
        self.patch(self.p.resource_manager.resource_type,
                   'default_report_fields', ())
        formatter = Formatter(self.p.resource_manager.resource_type)
        self.assertEqual(
            formatter.to_csv([self.records['full']]),
            [['InstanceId-1', '', 'LaunchTime-1']])

    def test_csv(self):
        p = self.load_policy({"name": "report-test-ec2", "resource": "ec2"})
        formatter = Formatter(p.resource_manager.resource_type)
        tests = [
            (["full"], ["full"]),
            (["minimal"], ["minimal"]),
            (["full", "minimal"], ["full", "minimal"]),
            (["full", "duplicate", "minimal"], ["full", "minimal"]),
        ]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)

    def test_custom_fields(self):
        # Test the ability to include custom fields.
        extra_fields = [
            "custom_field=CustomField",
            "missing_field=MissingField",
            "custom_tag=tag:CustomTag",
        ]

        # First do a test with adding custom fields to the normal ones
        formatter = Formatter(
            self.p.resource_manager.resource_type, extra_fields=extra_fields
        )
        recs = [self.records["full"]]
        rows = [self.rows["full_custom"]]
        self.assertEqual(formatter.to_csv(recs), rows)

        # Then do a test with only having custom fields
        formatter = Formatter(
            self.p.resource_manager.resource_type,
            extra_fields=extra_fields,
            include_default_fields=False,
        )
        recs = [self.records["full"]]
        rows = [self.rows["minimal_custom"]]
        self.assertEqual(formatter.to_csv(recs), rows)

    def test_formatter_jmespath_key(self):
        # models a k8s resource, or any that has a jmespath expression for
        # their id and name
        class FakeResource:
            class TypeInfo:
                id = 'metadata.uid'
                name = 'metadata.name'

        formatter = Formatter(
            resource_type=FakeResource.TypeInfo
        )
        records = [
            {'metadata': {'uid': 'foo', 'name': 'bar'}},
            {'metadata': {'uid': 'foo', 'name': 'bar'}}
        ]
        result = formatter.uniq_by_id(records=records)
        self.assertEqual(len(result), 1)


class TestASGReport(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["asg"]["records"]
        self.headers = data["asg"]["headers"]
        self.rows = data["asg"]["rows"]

    def test_csv(self):
        p = self.load_policy({"name": "report-test-asg", "resource": "asg"})
        formatter = Formatter(p.resource_manager.resource_type)
        tests = [
            (["full"], ["full"]),
            (["minimal"], ["minimal"]),
            (["full", "minimal"], ["full", "minimal"]),
            (["full", "duplicate", "minimal"], ["full", "minimal"]),
        ]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)


class TestELBReport(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["elb"]["records"]
        self.headers = data["elb"]["headers"]
        self.rows = data["elb"]["rows"]

    def test_csv(self):
        p = self.load_policy({"name": "report-test-elb", "resource": "elb"})
        formatter = Formatter(p.resource_manager.resource_type)
        tests = [
            (["full"], ["full"]),
            (["minimal"], ["minimal"]),
            (["full", "minimal"], ["full", "minimal"]),
            (["full", "duplicate", "minimal"], ["full", "minimal"]),
        ]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)


class TestMultiReport(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["ec2"]["records"]
        self.headers = data["ec2"]["headers"]
        self.rows = data["ec2"]["rows"]

    def test_csv(self):
        # Test the extra headers for multi-policy
        p = self.load_policy({"name": "report-test-ec2", "resource": "ec2"})
        formatter = Formatter(
            p.resource_manager.resource_type,
            include_region=True,
            include_policy=True,
        )
        tests = [(["minimal"], ["minimal_multipolicy"])]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)

    def test_s3_base_output_path(self):
        """When searching S3 to populate a report, the base output path
        should end with the policy name."""

        policy_name = "my_c7n_policy"
        output_paths = [
            f"logs/{policy_name}",
            f"/logs/{policy_name}",
            f"logs/{policy_name}/2021/01/01/01/",
            f"/logs/{policy_name}/with/more/extra/path/segments",
        ]

        self.assertTrue(all(
            strip_output_path(p, policy_name) == f"logs/{policy_name}"
            for p in output_paths
        ))


class TestGetValues(BaseTest):

    def test_get_values_with_at_fields(self):
        """Test _get_values handles fields starting with @ (like @odata.type) correctly."""
        record = {
            'id': 'test-id',
            'displayName': 'Test Location',
            '@odata.type': '#microsoft.graph.ipNamedLocation',
            'nested': {'field': 'nested-value'}
        }
        tag_map = {}

        # Test @ field extraction
        fields = ['@odata.type']
        result = _get_values(record, fields, tag_map)
        self.assertEqual(result, ['#microsoft.graph.ipNamedLocation'])

        # Test mixed fields (@ field and regular fields)
        fields = ['id', '@odata.type', 'displayName']
        result = _get_values(record, fields, tag_map)
        self.assertEqual(result, ['test-id', '#microsoft.graph.ipNamedLocation', 'Test Location'])

        # Test @ field that doesn't exist in record
        fields = ['@missing.field']
        result = _get_values(record, fields, tag_map)
        self.assertEqual(result, [''])

        # Test normal JMESPath still works
        fields = ['nested.field']
        result = _get_values(record, fields, tag_map)
        self.assertEqual(result, ['nested-value'])

    def test_formatter_with_at_fields(self):
        """Test Formatter end-to-end with @ fields like @odata.type."""
        # Create a fake resource type similar to Azure EntraID Named Location
        class FakeNamedLocationResource:
            class TypeInfo:
                id = 'id'
                name = 'displayName'
                date = 'createdDateTime'
                default_report_fields = ('displayName', 'createdDateTime', '@odata.type', 'id')

        formatter = Formatter(resource_type=FakeNamedLocationResource.TypeInfo)

        # Test record with @odata.type field
        records = [{
            'id': 'location-1',
            'displayName': 'Corporate IP Ranges',
            'createdDateTime': '2023-01-01T00:00:00Z',
            '@odata.type': '#microsoft.graph.ipNamedLocation'
        }]

        result = formatter.to_csv(records)
        expected = [['Corporate IP Ranges', '2023-01-01T00:00:00Z', '#microsoft.graph.ipNamedLocation', 'location-1']]
        self.assertEqual(result, expected)
