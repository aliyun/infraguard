resource "alicloud_log_store" "byok" {
  project          = "my-project"
  name             = "my-logstore"
  retention_period = 30
  shard_count      = 3

  encrypt_conf {
    enable       = true
    encrypt_type = "default"

    user_cmk_info {
      cmk_key_id = "key-xxx-123"
      arn        = "acs:kms:cn-hangzhou:123456:key/key-xxx-123"
      region_id  = "cn-hangzhou"
    }
  }
}
