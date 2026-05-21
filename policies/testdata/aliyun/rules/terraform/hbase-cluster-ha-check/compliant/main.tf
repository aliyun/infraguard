resource "alicloud_hbase_instance" "compliant" {
  name                   = "test-hbase"
  zone_id                = "cn-hangzhou-h"
  engine                 = "hbase"
  engine_version         = "2.0"
  master_instance_type   = "hbase.sn2.large"
  core_instance_type     = "hbase.sn2.large"
  core_instance_quantity = 3
  core_disk_type         = "cloud_ssd"
  core_disk_size         = 100
  pay_type               = "PostPaid"
}
