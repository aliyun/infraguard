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

resource "alicloud_oss_bucket" "compliant" {
  bucket          = "my-compliant-bucket"
  acl             = "private"
  redundancy_type = "ZRS"

  logging {
    target_bucket = "my-log-bucket"
  }

  server_side_encryption_rule {
    sse_algorithm     = "KMS"
    kms_master_key_id = "key-12345"
  }

  versioning {
    status = "Enabled"
  }

  referer_config {
    referers = ["https://example.com"]
  }

  policy = "{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":[\"China\"],\"Action\":[\"oss:*\"],\"Resource\":[\"acs:oss:*:*:my-compliant-bucket/*\"],\"Condition\":{\"Bool\":{\"acs:SecureTransport\":\"false\"},\"IpAddress\":{\"acs:SourceIp\":[\"192.168.0.0/16\"]}}}]}"
}

resource "alicloud_oss_bucket_replication" "compliant" {
  bucket = "my-compliant-bucket"
}
