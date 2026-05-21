resource "alicloud_vpn_gateway" "ssl_enabled" {
  name                 = "my-vpn-gateway"
  vpc_id               = "vpc-abc123"
  bandwidth            = 10
  instance_charge_type = "PostPaid"
  ssl_vpn              = "enable"
  vswitch_id           = "vsw-abc123"
}
