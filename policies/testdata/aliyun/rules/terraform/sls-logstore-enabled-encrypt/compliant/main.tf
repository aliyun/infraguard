resource "alicloud_log_store" "encrypted" {
  project               = "my-project"
  name                  = "my-logstore"
  retention_period      = 30
  shard_count           = 3

  encrypt_conf {
    enable       = true
    encrypt_type = "default"
  }
}
