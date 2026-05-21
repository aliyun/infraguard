resource "alicloud_actiontrail_trail" "compliant" {
  trail_name = "compliant-trail"
  event_rw   = "All"
  status     = "Enable"
}

resource "alicloud_cloud_firewall_control_policy" "compliant" {
  direction   = "in"
  acl_action  = "drop"
  proto       = "TCP"
  source      = "0.0.0.0/0"
  source_type = "net"
  destination = "10.0.0.0/8"
  dest_port   = "22/22"
}

resource "alicloud_instance" "compliant" {
  instance_type        = "ecs.g6.large"
  image_id             = "ubuntu_22_04_x64_20G_alibase_20230815.vhd"
  instance_charge_type = "PostPaid"
  vswitch_id           = "vsw-12345"
  security_groups      = ["sg-12345"]
  deletion_protection  = true
  key_pair_name        = "my-key-pair"
  ram_role_name        = "my-role"

  metadata_options {
    http_tokens = "required"
  }
}
