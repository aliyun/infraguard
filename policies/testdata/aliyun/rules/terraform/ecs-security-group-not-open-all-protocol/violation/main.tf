resource "alicloud_security_group_rule" "all_protocols" {
  type              = "ingress"
  ip_protocol       = "all"
  port_range        = "-1/-1"
  security_group_id = "sg-xxx"
  cidr_ip           = "10.0.0.0/8"
}
