resource "alicloud_mongodb_instance" "no_multi_zone" {
  engine_version       = "4.4"
  db_instance_class    = "dds.mongo.standard"
  db_instance_storage  = 20
  vswitch_id           = "vsw-12345"
  instance_charge_type = "PostPaid"
}
