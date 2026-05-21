resource "alicloud_vpn_connection" "health_check_enabled" {
  name                = "my-vpn-connection"
  vpn_gateway_id      = "vpn-abc123"
  customer_gateway_id = "cgw-abc123"
  local_subnet        = ["192.168.1.0/24"]
  remote_subnet       = ["10.0.0.0/24"]

  health_check_config {
    enable   = true
    dip      = "10.0.0.1"
    sip      = "192.168.1.1"
    interval = 3
    retry    = 3
  }
}
