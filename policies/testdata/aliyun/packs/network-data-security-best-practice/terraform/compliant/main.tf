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

resource "alicloud_ecs_disk" "compliant" {
  zone_id              = "cn-hangzhou-i"
  category             = "cloud_regional_disk_auto"
  size                 = 40
  encrypted            = true
  kms_key_id           = "key-12345"
  enable_auto_snapshot = true
}

resource "alicloud_ecs_disk_attachment" "compliant" {
  disk_id     = "compliant"
  instance_id = "i-12345"
}
