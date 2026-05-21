resource "alicloud_mongodb_instance" "low_storage" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 10
  vswitch_id          = "vsw-123456"
}
