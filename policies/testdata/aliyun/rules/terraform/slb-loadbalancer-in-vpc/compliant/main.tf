resource "alicloud_slb_load_balancer" "in_vpc" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
  vswitch_id         = "vsw-abc123"
}
