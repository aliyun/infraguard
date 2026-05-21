resource "alicloud_nat_gateway" "compliant" {
  vpc_id           = "vpc-123456"
  nat_gateway_name = "test-nat"
  payment_type     = "PayAsYouGo"
  vswitch_id       = "vsw-123456"
  nat_type         = "Enhanced"
}
