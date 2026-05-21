resource "alicloud_db_instance" "prepaid_no_renew" {
  engine               = "MySQL"
  engine_version       = "8.0"
  instance_type        = "rds.mysql.s3.large"
  instance_storage     = 100
  instance_charge_type = "Prepaid"
  period               = 1
  auto_renew           = false
}
