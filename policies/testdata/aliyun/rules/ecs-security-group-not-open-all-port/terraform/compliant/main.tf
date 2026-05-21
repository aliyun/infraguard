resource "alicloud_security_group_rule" "specific_port" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "443/443"
  security_group_id = "sg-xxx"
  cidr_ip           = "0.0.0.0/0"
}
