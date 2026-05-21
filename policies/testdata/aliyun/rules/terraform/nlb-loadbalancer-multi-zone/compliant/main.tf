resource "alicloud_nlb_load_balancer" "multi_zone" {
  load_balancer_name = "nlb-multi-zone"
  address_type       = "Internet"
  vpc_id             = "vpc-123456"

  zone_mappings {
    vswitch_id = "vsw-zone-a"
    zone_id    = "cn-hangzhou-h"
  }

  zone_mappings {
    vswitch_id = "vsw-zone-b"
    zone_id    = "cn-hangzhou-i"
  }
}
