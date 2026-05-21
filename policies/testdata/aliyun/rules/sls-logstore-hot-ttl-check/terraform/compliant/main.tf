resource "alicloud_log_store" "long_retention" {
  project          = "my-project"
  name             = "my-logstore"
  retention_period = 30
  shard_count      = 3
}
