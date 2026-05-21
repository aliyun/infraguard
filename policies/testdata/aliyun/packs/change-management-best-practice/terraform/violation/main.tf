resource "alicloud_db_instance" "no_maintain_time" {
  engine               = "MySQL"
  engine_version       = "8.0"
  instance_type        = "rds.mysql.s3.large"
  instance_storage     = 50
  instance_charge_type = "Postpaid"
  vswitch_id           = "vsw-12345"
}
