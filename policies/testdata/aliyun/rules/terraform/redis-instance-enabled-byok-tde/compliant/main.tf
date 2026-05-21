resource "alicloud_kvstore_instance" "tde_enabled" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  tde_status       = "Enabled"
}
