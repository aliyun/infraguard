resource "alicloud_kvstore_instance" "double_node" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  node_type        = "double"
}

resource "alicloud_kvstore_instance" "default_node" {
  db_instance_name = "my-redis-default"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
}
