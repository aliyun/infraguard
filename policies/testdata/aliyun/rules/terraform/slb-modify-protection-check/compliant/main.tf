resource "alicloud_slb_load_balancer" "protected" {
  load_balancer_name             = "my-slb"
  address_type                   = "intranet"
  modification_protection_status = "ConsoleProtection"
}
