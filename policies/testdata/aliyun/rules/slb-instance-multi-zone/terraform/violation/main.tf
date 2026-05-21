resource "alicloud_slb_load_balancer" "single_zone" {
  load_balancer_name = "my-slb"
  address_type       = "intranet"
  master_zone_id     = "cn-hangzhou-a"
}
