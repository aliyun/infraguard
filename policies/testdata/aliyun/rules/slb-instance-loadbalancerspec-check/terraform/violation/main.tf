resource "alicloud_slb_load_balancer" "violation" {
  load_balancer_name = "my-slb"
  load_balancer_spec = "slb.s4.large"
  address_type       = "intranet"
}
