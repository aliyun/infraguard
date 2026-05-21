resource "alicloud_alb_load_balancer" "single_zone" {
  load_balancer_name = "single-zone"

  zone_mappings {
    zone_id    = "cn-hangzhou-h"
    vswitch_id = "vsw-h"
  }
}
