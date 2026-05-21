resource "alicloud_db_instance" "open_whitelist" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
  security_ips     = ["0.0.0.0/0"]
}
