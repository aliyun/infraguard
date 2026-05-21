resource "alicloud_kvstore_instance" "with_backup_time" {
  db_instance_name = "my-redis"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  backup_time      = "02:00Z-03:00Z"
}
