resource "alicloud_kvstore_instance" "standard" {
  db_instance_name = "my-redis-standard"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
}
