resource "alicloud_kvstore_instance" "password_free" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  vpc_auth_mode    = "Close"
}
