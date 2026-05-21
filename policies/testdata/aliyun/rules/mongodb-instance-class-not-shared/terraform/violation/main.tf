resource "alicloud_mongodb_instance" "shared" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.shared.mid"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
}
