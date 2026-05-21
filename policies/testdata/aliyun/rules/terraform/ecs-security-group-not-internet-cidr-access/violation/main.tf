resource "alicloud_security_group_rule" "public_ingress" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = "sg-xxx"
  cidr_ip           = "203.0.113.0/24"
}
