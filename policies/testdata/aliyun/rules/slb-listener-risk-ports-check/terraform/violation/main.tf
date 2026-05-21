resource "alicloud_slb_listener" "risky_port" {
  load_balancer_id = "lb-abc123"
  frontend_port    = 22
  backend_port     = 22
  protocol         = "tcp"
  bandwidth        = 10
}
