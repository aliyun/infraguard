resource "alicloud_kvstore_instance" "restricted_ips" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  security_ips     = ["10.0.0.0/8", "172.16.0.0/12"]
}
