resource "alicloud_alb_load_balancer" "unprotected" {
  load_balancer_name         = "unprotected"
  deletion_protection_enabled = false
}
