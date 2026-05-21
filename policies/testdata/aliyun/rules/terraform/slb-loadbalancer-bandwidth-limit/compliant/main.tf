resource "alicloud_slb_load_balancer" "low_bandwidth" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
  bandwidth          = 100
}
