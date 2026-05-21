resource "alicloud_cen_transit_router_vpc_attachment" "multi_zone" {
  cen_id            = "cen-xxx"
  transit_router_id = "tr-xxx"
  vpc_id            = "vpc-xxx"

  zone_mappings {
    zone_id    = "cn-hangzhou-a"
    vswitch_id = "vsw-aaa"
  }

  zone_mappings {
    zone_id    = "cn-hangzhou-b"
    vswitch_id = "vsw-bbb"
  }
}
