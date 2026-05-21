resource "alicloud_polardb_cluster" "tde_enabled" {
  db_type       = "MySQL"
  db_version    = "8.0"
  db_node_class = "polar.mysql.x4.large"
  pay_type      = "PostPaid"
  vswitch_id    = "vsw-abc123"
  tde_status    = "Enabled"
}
