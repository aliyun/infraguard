resource "alicloud_db_instance" "autoscale_enabled" {
  engine             = "MySQL"
  engine_version     = "8.0"
  instance_type      = "rds.mysql.s3.large"
  instance_storage   = 100
  storage_auto_scale = "Enable"
}
