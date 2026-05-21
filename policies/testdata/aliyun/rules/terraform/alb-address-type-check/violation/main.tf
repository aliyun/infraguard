resource "alicloud_alb_load_balancer" "internet" {
  load_balancer_name = "internet"
  address_type       = "Internet"
}
