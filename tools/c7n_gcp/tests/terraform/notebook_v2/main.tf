provider "google" {}

resource "random_id" "suffix" {
  byte_length = 2
}

resource "google_workbench_instance" "instance" {
  name = "c7n-notebook-${terraform.workspace}-${random_id.suffix.hex}"
  location = "us-central1-a"
}