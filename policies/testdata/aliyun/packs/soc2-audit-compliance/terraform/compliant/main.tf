resource "alicloud_actiontrail_trail" "default" {
  trail_name      = "my-actiontrail"
  oss_bucket_name = "my-bucket"
  event_rw        = "All"
  status          = "Enable"
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
