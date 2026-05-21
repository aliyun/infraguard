resource "alicloud_db_instance" "basic_instance" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
  category         = "Basic"
}
