resource "alicloud_security_group_rule" "private_ingress" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = "sg-xxx"
  cidr_ip           = "10.0.0.0/8"
}
