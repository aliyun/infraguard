resource "alicloud_wafv3_instance" "without_logging" {
  log_status = false
}
