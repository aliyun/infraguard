resource "alicloud_kvstore_instance" "protected" {
  db_instance_name            = "my-redis"
  instance_class              = "redis.master.small.default"
  instance_type               = "Redis"
  vswitch_id                  = "vsw-abc123"
  instance_release_protection = true
}
