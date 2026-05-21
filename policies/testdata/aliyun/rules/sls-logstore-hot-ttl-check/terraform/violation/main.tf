resource "alicloud_log_store" "short_retention" {
  project          = "my-project"
  name             = "my-logstore"
  retention_period = 7
  shard_count      = 3
}
