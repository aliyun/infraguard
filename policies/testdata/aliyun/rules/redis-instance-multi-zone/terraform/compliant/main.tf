resource "alicloud_kvstore_instance" "multi_zone" {
  db_instance_name  = "my-redis"
  instance_class    = "redis.master.small.default"
  instance_type     = "Redis"
  vswitch_id        = "vsw-abc123"
  zone_id           = "cn-hangzhou-a"
  secondary_zone_id = "cn-hangzhou-b"
}
