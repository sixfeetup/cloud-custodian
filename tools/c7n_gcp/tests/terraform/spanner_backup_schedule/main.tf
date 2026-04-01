provider "google" {}


resource "google_spanner_instance" "c7n" {
  name         = "c7n-spanner-instance"
  display_name = "c7n-spanner-instance"
  config       = "regional-us-central1"
  num_nodes    = 1
}

resource "google_spanner_database" "c7n" {
  instance            = google_spanner_instance.c7n.name
  name                = "c7n-spanner-database"
  deletion_protection = false
}

resource "google_spanner_backup_schedule" "c7n_long_retention" {
  instance           = google_spanner_instance.c7n.name
  database           = google_spanner_database.c7n.name
  name               = "c7n-backup-schedule-long-retention"
  retention_duration = "2678400s"

  spec {
    cron_spec {
      text = "0 3 * * *"
    }
  }

  full_backup_spec {}

  depends_on = [google_spanner_database.c7n]
}
