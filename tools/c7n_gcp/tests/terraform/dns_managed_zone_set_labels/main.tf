provider "google" {}

resource "random_id" "suffix" {
  byte_length = 2
}

resource "google_dns_managed_zone" "default" {
  name        = "c7n-zone-${terraform.workspace}-${random_id.suffix.hex}"
  dns_name    = "c7n-${terraform.workspace}-${random_id.suffix.hex}.example.com."
  description = "Cloud Custodian managed zone label test"

  labels = {
    env = "default"
  }
}
