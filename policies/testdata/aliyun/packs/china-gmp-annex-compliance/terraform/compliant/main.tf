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

resource "alicloud_mongodb_instance" "compliant" {
  engine_version       = "4.4"
  db_instance_class    = "dds.mongo.standard"
  db_instance_storage  = 20
  vswitch_id           = "vsw-12345"
  zone_id              = "cn-hangzhou-a"
  secondary_zone_id    = "cn-hangzhou-b"
  release_protection   = true
  audit_status         = "enable"
  ssl_action           = "Open"
  network_type         = "VPC"
  replication_factor   = 3
  instance_charge_type = "PostPaid"
  tde_status           = "enabled"
  encryption_key       = "key-12345"
  security_ip_list     = ["10.0.0.0/8"]
}
