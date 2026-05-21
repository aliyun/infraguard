resource "alicloud_polardb_cluster" "restricted" {
  db_type    = "MySQL"
  db_version = "8.0"
  db_node_class = "polar.mysql.x4.large"
  vswitch_id = "vsw-abc12345"
  zone_id    = "cn-hangzhou-h"
  pay_type   = "PostPaid"
  security_ips = ["10.0.0.0/8", "172.16.0.0/12"]
}
