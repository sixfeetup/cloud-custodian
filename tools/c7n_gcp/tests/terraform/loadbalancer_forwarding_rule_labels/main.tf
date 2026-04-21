variable "google_project_id" {
  description = "GCP project ID"
}

provider "google" {
  project = var.google_project_id
  region  = "us-central1"
}

resource "random_id" "suffix" {
  byte_length = 2
}

locals {
  forwarding_rule_name = "c7n-forwarding-rule-${terraform.workspace}-${random_id.suffix.hex}"
  target_pool_name     = "c7n-target-pool-${terraform.workspace}-${random_id.suffix.hex}"
}

resource "google_compute_target_pool" "default" {
  name   = local.target_pool_name
  region = "us-central1"
}

resource "google_compute_forwarding_rule" "default" {
  name       = local.forwarding_rule_name
  region     = "us-central1"
  target     = google_compute_target_pool.default.id
  port_range = "80"
  ip_protocol = "TCP"

  labels = {
    env = "default"
  }
}
