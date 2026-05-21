resource "alicloud_mongodb_instance" "vpc_network" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 50
  vswitch_id          = "vsw-123456"
  network_type        = "VPC"
}
