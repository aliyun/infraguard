resource "alicloud_db_instance" "single_az" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
  zone_id          = "cn-hangzhou-a"
}
