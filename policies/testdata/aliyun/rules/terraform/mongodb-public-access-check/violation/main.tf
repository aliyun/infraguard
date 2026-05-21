resource "alicloud_mongodb_instance" "public_access" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
  security_ip_list    = ["0.0.0.0/0"]
}
