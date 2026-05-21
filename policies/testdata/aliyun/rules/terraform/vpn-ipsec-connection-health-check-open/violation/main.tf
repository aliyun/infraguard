resource "alicloud_vpn_connection" "no_health_check" {
  name                = "my-vpn-connection"
  vpn_gateway_id      = "vpn-abc123"
  customer_gateway_id = "cgw-abc123"
  local_subnet        = ["192.168.1.0/24"]
  remote_subnet       = ["10.0.0.0/24"]
}
