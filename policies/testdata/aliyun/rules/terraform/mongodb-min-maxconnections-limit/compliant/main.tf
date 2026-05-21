resource "alicloud_mongodb_instance" "standard_class" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.standard"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
}
