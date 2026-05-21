resource "alicloud_lindorm_instance" "violation" {
  instance_name             = "test-lindorm"
  disk_category             = "cloud_ssd"
  payment_type              = "PayAsYouGo"
  vswitch_id                = "vsw-123456"
  table_engine_node_count   = 2
  table_engine_specification = "lindorm.g.xlarge"
  zone_id                   = "cn-hangzhou-h"
}
