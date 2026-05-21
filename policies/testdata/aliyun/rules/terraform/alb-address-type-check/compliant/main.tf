resource "alicloud_alb_load_balancer" "internal" {
  load_balancer_name = "internal"
  address_type       = "Intranet"
}
