resource "alicloud_alb_load_balancer" "secured" {
  load_balancer_name = "secured"
  security_group_ids = ["sg-12345"]
}
