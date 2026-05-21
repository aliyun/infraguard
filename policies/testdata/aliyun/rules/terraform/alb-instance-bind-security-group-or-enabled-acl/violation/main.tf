resource "alicloud_alb_load_balancer" "open" {
  load_balancer_name = "open"
  security_group_ids = []
}
