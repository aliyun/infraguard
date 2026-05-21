resource "alicloud_alb_load_balancer" "single_zone" {
  load_balancer_name    = "single-zone-alb"
  address_type          = "Intranet"
  load_balancer_edition = "Standard"

  zone_mappings {
    zone_id    = "cn-hangzhou-a"
    vswitch_id = "vsw-aaa"
  }
}
