resource "alicloud_kvstore_instance" "no_vpc" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
}
