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

resource "alicloud_ram_policy" "compliant" {
  policy_name     = "compliant-policy"
  policy_document = "{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ecs:Describe*\",\"Resource\":\"acs:ecs:*:*:instance/*\"}]}"
}

resource "alicloud_ram_role_policy_attachment" "compliant" {
  policy_name = "compliant-policy"
  policy_type = "Custom"
  role_name   = "my-role"
}
