resource "alicloud_kvstore_instance" "ssl_enabled" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  ssl_enable       = "Enable"
}
