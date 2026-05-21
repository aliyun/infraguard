resource "alicloud_waf_instance" "with_logging" {
  big_screen   = "0"
  log_status   = "1"
  log_storage  = "3"
}
