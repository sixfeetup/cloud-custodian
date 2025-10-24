terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Create test users
resource "aws_iam_user" "test_user_1" {
  name = "c7n-test-user-1"
  path = "/c7n-test/"

  tags = {
    Environment = "test"
    Purpose     = "cloud-custodian-testing"
  }
}

resource "aws_iam_user" "test_user_2" {
  name = "c7n-test-user-2"
  path = "/c7n-test/"

  tags = {
    Environment = "test"
    Purpose     = "cloud-custodian-testing"
  }
}

# Create access keys for the users
resource "aws_iam_access_key" "user_1_key_1" {
  user = aws_iam_user.test_user_1.name
}

resource "aws_iam_access_key" "user_2_key_1" {
  user = aws_iam_user.test_user_2.name
}

# Create a second access key for user 1 (will be deactivated)
resource "aws_iam_access_key" "user_1_key_2" {
  user   = aws_iam_user.test_user_1.name
  status = "Inactive"
}
