resource "alicloud_tsdb_instance" "open_access" {
  payment_type     = "PayAsYouGo"
  vswitch_id       = "vsw-xxx"
  instance_class   = "tsdb.1x.basic"
  instance_storage = "50"
  engine_type      = "tsdb_tsdb"
  security_ip_list = ["0.0.0.0/0"]
}
