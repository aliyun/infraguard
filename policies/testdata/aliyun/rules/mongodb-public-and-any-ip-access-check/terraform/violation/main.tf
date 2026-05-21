resource "alicloud_mongodb_instance" "classic_network" {
  engine_version      = "4.4"
  db_instance_class   = "dds.mongo.mid"
  db_instance_storage = 50
  network_type        = "Classic"
}
