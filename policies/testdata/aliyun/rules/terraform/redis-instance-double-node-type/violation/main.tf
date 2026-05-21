resource "alicloud_kvstore_instance" "single_node" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  node_type        = "single"
}
