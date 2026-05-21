resource "alicloud_polardb_cluster" "unprotected" {
  db_type       = "MySQL"
  db_version    = "8.0"
  db_node_class = "polar.mysql.x4.large"
  pay_type      = "PostPaid"
  vswitch_id    = "vsw-abc123"
  deletion_lock = 0
}
