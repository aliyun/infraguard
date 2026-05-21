resource "alicloud_kvstore_instance" "auth_enabled" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  vpc_auth_mode    = "Open"
}

resource "alicloud_kvstore_instance" "auth_default" {
  db_instance_name = "my-redis-default"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
}
