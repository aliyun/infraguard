resource "alicloud_alb_load_balancer" "basic" {
  load_balancer_name   = "basic"
  load_balancer_edition = "Standard"
}
