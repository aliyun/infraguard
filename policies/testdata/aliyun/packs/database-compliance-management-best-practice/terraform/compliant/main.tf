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

resource "alicloud_db_instance" "compliant" {
  engine               = "MySQL"
  engine_version       = "8.0"
  instance_type        = "rds.mysql.s3.large"
  instance_storage     = 50
  instance_charge_type = "Postpaid"
  vswitch_id           = "vsw-12345"
  zone_id_slave_a      = "cn-hangzhou-b"
  maintain_time        = "02:00Z-06:00Z"
  ssl_action           = "Open"
  sql_collector_status = "Enabled"
  enable_backup_log    = true
  deletion_protection  = true
  encryption_key       = "key-12345"
  category             = "HighAvailability"
  storage_auto_scale   = "Enable"
  security_ips         = ["10.0.0.0/8"]
}
