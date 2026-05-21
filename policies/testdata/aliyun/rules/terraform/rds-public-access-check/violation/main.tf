resource "alicloud_db_instance" "default" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s3.large"
  instance_storage = 100
}

resource "alicloud_db_connection" "public" {
  instance_id       = "rm-abc12345"
  connection_prefix = "my-rds-public"
}
