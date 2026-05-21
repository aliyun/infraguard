resource "alicloud_mongodb_instance" "audit_enabled" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
  audit_status        = "enable"
}
