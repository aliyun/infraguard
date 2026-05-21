resource "alicloud_slb_load_balancer" "with_log" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
  access_log         = "enabled"
}
