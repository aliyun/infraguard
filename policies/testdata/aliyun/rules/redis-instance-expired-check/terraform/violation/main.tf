resource "alicloud_kvstore_instance" "prepaid_no_auto_renew" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  payment_type     = "PrePaid"
}
