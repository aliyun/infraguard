resource "alicloud_mongodb_instance" "multi_zone" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
  zone_id             = "cn-hangzhou-h"
  secondary_zone_id   = "cn-hangzhou-g"
}
