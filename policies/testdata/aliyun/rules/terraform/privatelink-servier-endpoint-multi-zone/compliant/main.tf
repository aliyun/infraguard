resource "alicloud_privatelink_vpc_endpoint" "multi_zone" {
  service_id         = "epsrv-abc123"
  vpc_id             = "vpc-abc123"
  endpoint_description = "Multi-zone endpoint"

  zone {
    zone_id    = "cn-hangzhou-h"
    vswitch_id = "vsw-h"
  }

  zone {
    zone_id    = "cn-hangzhou-i"
    vswitch_id = "vsw-i"
  }
}
