resource "alicloud_alb_load_balancer" "protected" {
  load_balancer_name         = "protected"
  deletion_protection_enabled = true
}
