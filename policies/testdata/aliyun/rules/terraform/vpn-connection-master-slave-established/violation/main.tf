resource "alicloud_vpn_connection" "default" {
  name                = "my-vpn-connection"
  vpn_gateway_id      = "vpn-gw-abc123"
  customer_gateway_id = "cgw-abc123"

  tunnel_options_specification {
    tunnel_ipsec_config {
      ipsec_auth_alg = "sha256"
      ipsec_enc_alg  = "aes256"
    }
    role = "master"
  }
}
