resource "alicloud_security_group_rule" "ssh_private" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = "sg-xxx"
  cidr_ip           = "10.0.0.0/8"
}

resource "alicloud_security_group_rule" "https_public" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "443/443"
  security_group_id = "sg-xxx"
  cidr_ip           = "0.0.0.0/0"
}
