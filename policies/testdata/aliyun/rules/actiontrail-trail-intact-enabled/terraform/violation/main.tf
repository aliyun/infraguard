resource "alicloud_actiontrail_trail" "default" {
  trail_name         = "my-actiontrail"
  oss_bucket_name    = "my-bucket"
  event_rw           = "Write"
  status             = "Enable"
}
