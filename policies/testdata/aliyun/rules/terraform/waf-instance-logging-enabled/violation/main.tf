resource "alicloud_waf_instance" "without_logging" {
  big_screen   = "0"
  log_status   = "0"
  log_storage  = "3"
}
