resource "alicloud_nat_gateway" "violation" {
  nat_gateway_name = "test-nat"
  payment_type     = "PayAsYouGo"
  vswitch_id       = "vsw-123456"
  nat_type         = "Enhanced"
  network_type     = "internet"
}
