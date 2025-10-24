terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Create a test user with no access keys for edge case testing
resource "aws_iam_user" "test_user_empty" {
  name = "c7n-test-user-empty"
  path = "/c7n-test/"

  tags = {
    Environment = "test"
    Purpose     = "cloud-custodian-testing"
  }
}
