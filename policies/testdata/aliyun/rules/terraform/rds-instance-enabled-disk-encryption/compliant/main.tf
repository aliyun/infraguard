resource "alicloud_db_instance" "encrypted" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
  encryption_key   = "kms-key-id-12345"
}
