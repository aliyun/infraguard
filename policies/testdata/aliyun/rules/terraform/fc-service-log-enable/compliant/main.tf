resource "alicloud_fc_service" "compliant" {
  name = "test-service"

  log_config {
    project  = "my-project"
    logstore = "my-logstore"
  }
}
