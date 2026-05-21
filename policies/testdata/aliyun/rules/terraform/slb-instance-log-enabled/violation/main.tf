resource "alicloud_slb_load_balancer" "no_log" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
}
