resource "alicloud_db_instance" "private_only" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
  security_ips     = ["10.0.0.0/24", "172.16.0.0/16"]
}
