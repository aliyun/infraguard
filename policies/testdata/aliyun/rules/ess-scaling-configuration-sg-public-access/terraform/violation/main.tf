resource "alicloud_ess_scaling_configuration" "open" {
  scaling_group_id  = "asg-123"
  image_id          = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  instance_type     = "ecs.s6-c1m1.small"
  security_group_id = "sg-open"
}

resource "alicloud_security_group_rule" "open_ssh" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = "sg-open"
  cidr_ip           = "0.0.0.0/0"
}
