resource "alicloud_slb_load_balancer" "multi_zone" {
  load_balancer_name = "my-slb"
  address_type       = "internet"
  master_zone_id     = "cn-hangzhou-a"
  slave_zone_id      = "cn-hangzhou-b"
}
