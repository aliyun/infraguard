resource "alicloud_polardb_cluster" "prepaid_auto_renew" {
  db_type        = "MySQL"
  db_version     = "8.0"
  db_node_class  = "polar.mysql.x4.large"
  pay_type       = "PrePaid"
  vswitch_id     = "vsw-abc123"
  renewal_status = "AutoRenewal"
  auto_renew_period = 1
}
