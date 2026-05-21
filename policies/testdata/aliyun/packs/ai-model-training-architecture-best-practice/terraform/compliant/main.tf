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

resource "alicloud_nas_file_system" "compliant" {
  protocol_type = "NFS"
  storage_type  = "Performance"
  encrypt_type  = 1
}
