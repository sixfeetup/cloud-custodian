provider "google" {}

resource "random_id" "suffix" {
  byte_length = 2
}

output "endpoint_display_name" {
  value = "c7n-test-get-resource-endpoint-${terraform.workspace}-${random_id.suffix.hex}"
}
