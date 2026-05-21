resource "alicloud_slb_load_balancer" "internal" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
  vswitch_id         = "vsw-abc123"
}
