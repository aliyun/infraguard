resource "alicloud_security_group_rule" "all_egress" {
  type              = "egress"
  ip_protocol       = "all"
  port_range        = "-1/-1"
  security_group_id = "sg-xxx"
  cidr_ip           = "0.0.0.0/0"
}
