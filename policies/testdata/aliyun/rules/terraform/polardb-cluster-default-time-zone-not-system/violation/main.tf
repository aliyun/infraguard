resource "alicloud_polardb_cluster" "unconfigured" {
  db_type    = "MySQL"
  db_version = "8.0"
  pay_type   = "PostPaid"
  vswitch_id = "vsw-abc123"
}
