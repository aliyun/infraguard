resource "alicloud_security_group_rule" "http_public" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "80/80"
  security_group_id = "sg-xxx"
  cidr_ip           = "0.0.0.0/0"
}
