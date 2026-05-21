resource "alicloud_privatelink_vpc_endpoint" "single_zone" {
  service_id         = "epsrv-abc123"
  vpc_id             = "vpc-abc123"
  endpoint_description = "Single-zone endpoint"

  zone {
    zone_id    = "cn-hangzhou-h"
    vswitch_id = "vsw-h"
  }
}
