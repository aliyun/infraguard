resource "alicloud_polardb_cluster" "with_maintain_time" {
  db_type       = "MySQL"
  db_version    = "8.0"
  db_node_class = "polar.mysql.x4.large"
  pay_type      = "PostPaid"
  vswitch_id    = "vsw-abc123"
  maintain_time = "02:00Z-03:00Z"
}
