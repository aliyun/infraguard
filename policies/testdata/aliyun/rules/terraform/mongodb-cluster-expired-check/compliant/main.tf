resource "alicloud_mongodb_instance" "prepaid_auto_renew" {
  engine_version       = "4.4"
  db_instance_class    = "dds.mongo.mid"
  db_instance_storage  = 50
  vswitch_id           = "vsw-123456"
  instance_charge_type = "PrePaid"
  auto_renew           = true
}
