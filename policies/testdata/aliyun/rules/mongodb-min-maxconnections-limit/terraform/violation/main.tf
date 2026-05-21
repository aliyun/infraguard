resource "alicloud_mongodb_instance" "small_class" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.small"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
}
