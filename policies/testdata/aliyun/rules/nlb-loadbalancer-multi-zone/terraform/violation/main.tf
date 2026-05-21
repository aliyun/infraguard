resource "alicloud_nlb_load_balancer" "single_zone" {
  load_balancer_name = "nlb-single-zone"
  address_type       = "Internet"
  vpc_id             = "vpc-123456"

  zone_mappings {
    vswitch_id = "vsw-zone-a"
    zone_id    = "cn-hangzhou-h"
  }
}
