resource "alicloud_db_instance" "in_vpc" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
  vswitch_id       = "vsw-abc12345"
}
