resource "alicloud_log_store" "no_encrypt" {
  project          = "my-project"
  name             = "my-logstore"
  retention_period = 30
  shard_count      = 3
}
