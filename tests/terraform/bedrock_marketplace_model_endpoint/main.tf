# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Resources needed to create a Bedrock Marketplace model endpoint: only the
# SageMaker execution role. The endpoint itself isn't defined here -- the AWS
# provider has no resource for it (hashicorp/terraform-provider-aws#41370).
# The `create_marketplace_model_endpoint` fixture in
# tests/test_bedrock_marketplace.py creates and deletes it directly through
# the API. See README.md.

provider "aws" {
  region = "us-east-1"
}

resource "random_id" "suffix" {
  byte_length = 2
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["sagemaker.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "endpoint_execution" {
  name               = "c7n-bedrock-marketplace-endpoint-${random_id.suffix.hex}"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "endpoint_execution-AmazonSageMakerFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
  role       = aws_iam_role.endpoint_execution.name
}

output "execution_role_arn" {
  value = aws_iam_role.endpoint_execution.arn
}
