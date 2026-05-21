resource "alicloud_cen_transit_router_peer_attachment" "insufficient_bandwidth" {
  cen_id                                = "cen-1234567890"
  transit_router_id                     = "tr-cn-hangzhou"
  peer_transit_router_region_id         = "cn-shanghai"
  peer_transit_router_id                = "tr-cn-shanghai"
  bandwidth                             = 1
  transit_router_attachment_name        = "insufficient-bandwidth"
  transit_router_attachment_description = "Cross-region connection with insufficient bandwidth"
}
