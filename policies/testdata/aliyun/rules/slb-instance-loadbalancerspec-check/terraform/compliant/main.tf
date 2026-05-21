resource "alicloud_slb_load_balancer" "compliant" {
  load_balancer_name = "my-slb"
  load_balancer_spec = "slb.s2.small"
  address_type       = "intranet"
}
