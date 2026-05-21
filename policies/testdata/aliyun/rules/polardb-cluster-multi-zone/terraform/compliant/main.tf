resource "alicloud_polardb_cluster" "multi_zone" {
  db_type    = "MySQL"
  db_version = "8.0"
  db_node_class = "polar.mysql.x4.large"
  vswitch_id = "vsw-abc12345"
  zone_id    = "cn-hangzhou-MAZ5(h,i)"
  pay_type   = "PostPaid"
}
