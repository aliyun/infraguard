resource "alicloud_polardb_cluster" "single_zone" {
  db_type    = "MySQL"
  db_version = "8.0"
  db_node_class = "polar.mysql.x4.large"
  vswitch_id = "vsw-abc12345"
  zone_id    = "cn-hangzhou-h"
  pay_type   = "PostPaid"
}
