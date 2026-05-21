resource "alicloud_slb_load_balancer" "high_bandwidth" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
  bandwidth          = 1000
}
