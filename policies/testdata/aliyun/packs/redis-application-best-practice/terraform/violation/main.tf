resource "alicloud_kvstore_instance" "default" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  engine_version   = "5.0"
  zone_id          = "cn-hangzhou-h"
}
