resource "alicloud_slb_load_balancer" "default" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
  delete_protection  = "off"
}
