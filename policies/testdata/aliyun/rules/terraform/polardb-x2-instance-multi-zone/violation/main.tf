resource "alicloud_drds_polardbx_instance" "single_zone" {
  name       = "polardbx-test"
  cn_class   = "polarx.x4.large.2e"
  dn_class   = "mysql.x4.large.25e"
  cn_node_count = 2
  dn_node_count = 2
  vpc_id     = "vpc-xxx"
  zone_id    = "cn-hangzhou-h"
}
