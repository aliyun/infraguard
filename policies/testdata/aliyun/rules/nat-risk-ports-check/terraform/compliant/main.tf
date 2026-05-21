resource "alicloud_forward_entry" "compliant" {
  forward_table_id = "ftb-123456"
  external_ip      = "1.2.3.4"
  external_port    = "80"
  ip_protocol      = "tcp"
  internal_ip      = "10.0.0.1"
  internal_port    = "80"
}
