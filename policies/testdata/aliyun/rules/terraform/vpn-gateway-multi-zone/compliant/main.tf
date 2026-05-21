resource "alicloud_vpn_gateway" "multi_zone" {
  name                          = "my-vpn-gateway"
  vpc_id                        = "vpc-abc123"
  bandwidth                     = 10
  instance_charge_type          = "PostPaid"
  vswitch_id                    = "vsw-abc123"
  disaster_recovery_vswitch_id  = "vsw-def456"
}
