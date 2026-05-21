resource "alicloud_slb_load_balancer" "public" {
  load_balancer_name = "my-slb"
  address_type       = "internet"
}
