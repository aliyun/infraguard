resource "alicloud_mongodb_instance" "restricted" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
  security_ip_list    = ["10.0.0.0/8", "172.16.0.0/12"]
}
