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

resource "alicloud_alb_load_balancer" "compliant" {
  load_balancer_name          = "compliant-alb"
  address_type                = "Intranet"
  load_balancer_edition       = "StandardWithWaf"
  deletion_protection_enabled = true
  security_group_ids          = ["sg-12345"]

  zone_mappings {
    zone_id    = "cn-hangzhou-a"
    vswitch_id = "vsw-aaa"
  }

  zone_mappings {
    zone_id    = "cn-hangzhou-b"
    vswitch_id = "vsw-bbb"
  }
}
