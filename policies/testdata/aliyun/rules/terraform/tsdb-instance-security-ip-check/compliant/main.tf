resource "alicloud_tsdb_instance" "restricted" {
  payment_type     = "PayAsYouGo"
  vswitch_id       = "vsw-xxx"
  instance_class   = "tsdb.1x.basic"
  instance_storage = "50"
  engine_type      = "tsdb_tsdb"
  security_ip_list = ["10.0.0.0/24", "172.16.0.0/16"]
}
