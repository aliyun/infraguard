resource "alicloud_alb_load_balancer" "multi_zone" {
  load_balancer_name = "multi-zone"

  zone_mappings {
    zone_id    = "cn-hangzhou-h"
    vswitch_id = "vsw-h"
  }

  zone_mappings {
    zone_id    = "cn-hangzhou-i"
    vswitch_id = "vsw-i"
  }
}
