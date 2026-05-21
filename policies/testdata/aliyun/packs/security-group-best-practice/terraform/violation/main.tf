resource "alicloud_security_group_rule" "allow_all" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "-1/-1"
  cidr_ip           = "0.0.0.0/0"
  security_group_id = "sg-xxx"
  policy            = "accept"
}
