resource "alicloud_alb_load_balancer" "with_waf" {
  load_balancer_name    = "with-waf"
  load_balancer_edition = "StandardWithWaf"
}
