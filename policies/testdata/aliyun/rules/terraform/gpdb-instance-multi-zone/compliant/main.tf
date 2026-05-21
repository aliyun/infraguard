resource "alicloud_gpdb_instance" "compliant" {
  db_instance_mode  = "StorageElastic"
  engine            = "gpdb"
  engine_version    = "6.0"
  instance_spec     = "2C16G"
  vswitch_id        = "vsw-123456"
  seg_node_num      = 4
  seg_storage_type  = "cloud_essd"
  storage_size      = 50
  availability_zone = "cn-hangzhou-h"
  standby_zone_id   = "cn-hangzhou-g"
}
