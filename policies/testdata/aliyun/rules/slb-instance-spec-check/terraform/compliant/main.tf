resource "alicloud_slb_load_balancer" "good_spec" {
  load_balancer_name = "my-slb"
  load_balancer_spec = "slb.s3.medium"
  address_type       = "intranet"
}
