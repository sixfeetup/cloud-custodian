provider "aws" {}

resource "random_pet" "profile" {
  length    = 2
  separator = "-"
}

resource "aws_s3_bucket" "logging" {
  bucket        = "c7n-bedrock-model-invocation-logging-${random_pet.profile.id}"
  force_destroy = true
}

resource "aws_bedrock_inference_profile" "test_profile" {
  name        = "c7n-test-profile-${substr(uuid(), 0, 8)}"
  description = "Test profile for C7N"

  model_source {
    copy_from = "arn:aws:bedrock:us-east-1::inference-profile/global.amazon.nova-2-lite-v1:0"
  }

  tags = {
    Environment = "test"
    Owner       = "c7n"
  }
}

resource "aws_bedrock_model_invocation_logging_configuration" "enabled" {
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = false
    embedding_data_delivery_enabled = false

    s3_config {
      bucket_name = aws_s3_bucket.logging.id
      key_prefix  = "bedrock/model-invocation-logging/"
    }
  }
}
