resource "alicloud_instance" "web" {
  instance_type = "ecs.g6.large"
  image_id      = "ubuntu_20_04_x64_20G_alibase_20210623.vhd"
}

resource "alicloud_cloud_firewall_control_policy" "default" {
  direction        = "in"
  application_name = "ANY"
  description      = "deny all inbound"
  acl_action       = "drop"
  source           = "0.0.0.0/0"
  source_type      = "net"
  destination      = "0.0.0.0/0"
  destination_type = "net"
  proto            = "ANY"
}
