resource "alicloud_alb_load_balancer" "without_waf" {
  load_balancer_name    = "without-waf"
  load_balancer_edition = "Standard"
}
