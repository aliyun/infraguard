resource "alicloud_slb_load_balancer" "classic" {
  load_balancer_name = "my-slb"
  address_type       = "internet"
}
