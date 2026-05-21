resource "alicloud_polardb_cluster" "not_in_vpc" {
  db_type    = "MySQL"
  db_version = "8.0"
  db_node_class = "polar.mysql.x4.large"
  zone_id    = "cn-hangzhou-h"
  pay_type   = "PostPaid"
}
