resource "alicloud_gwlb_load_balancer" "compliant" {
  load_balancer_name = "test-gwlb"
  vpc_id             = "vpc-123456"

  zone_mappings {
    vswitch_id = "vsw-zone-a"
    zone_id    = "cn-hangzhou-h"
  }

  zone_mappings {
    vswitch_id = "vsw-zone-b"
    zone_id    = "cn-hangzhou-g"
  }
}
