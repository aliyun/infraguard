resource "alicloud_slb_load_balancer" "low_spec" {
  load_balancer_name = "my-slb"
  load_balancer_spec = "slb.s1.small"
  address_type       = "intranet"
}
