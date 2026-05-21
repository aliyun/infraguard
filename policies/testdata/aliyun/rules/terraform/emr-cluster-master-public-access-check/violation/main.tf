resource "alicloud_emr_cluster" "violation" {
  name              = "test-cluster"
  emr_ver           = "EMR-3.38.0"
  cluster_type      = "HADOOP"
  zone_id           = "cn-hangzhou-h"
  security_group_id = "sg-123456"
  vswitch_id        = "vsw-123456"
  charge_type       = "PostPaid"
  is_open_public_ip = true
}
