resource "alicloud_kvstore_instance" "open_whitelist" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  security_ips     = ["0.0.0.0/0"]
}
