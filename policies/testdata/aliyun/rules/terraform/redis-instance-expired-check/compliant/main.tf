resource "alicloud_kvstore_instance" "prepaid_with_auto_renew" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  payment_type     = "PrePaid"
  auto_renew       = true
}

resource "alicloud_kvstore_instance" "postpaid" {
  db_instance_name = "my-redis-postpaid"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  payment_type     = "PostPaid"
}
