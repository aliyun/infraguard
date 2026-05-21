resource "alicloud_kvstore_instance" "sufficient_capacity" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  capacity         = 2048
}

resource "alicloud_kvstore_instance" "default_capacity" {
  db_instance_name = "my-redis-default"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
}
