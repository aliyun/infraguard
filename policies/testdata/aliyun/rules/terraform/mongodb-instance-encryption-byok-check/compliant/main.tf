resource "alicloud_mongodb_instance" "tde_with_byok" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
  tde_status          = "enabled"
  encryption_key      = "kms-key-123"
}
