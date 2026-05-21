resource "alicloud_db_instance" "with_maintain_time" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
  maintain_time    = "02:00Z-06:00Z"
}
