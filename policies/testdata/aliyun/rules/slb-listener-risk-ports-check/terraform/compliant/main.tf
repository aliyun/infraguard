resource "alicloud_slb_listener" "safe_port" {
  load_balancer_id = "lb-abc123"
  frontend_port    = 443
  backend_port     = 443
  protocol         = "https"
  bandwidth        = 10
}
