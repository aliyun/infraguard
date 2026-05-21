resource "alicloud_security_group_rule" "all_public" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "-1/-1"
  security_group_id = "sg-xxx"
  cidr_ip           = "0.0.0.0/0"
}
