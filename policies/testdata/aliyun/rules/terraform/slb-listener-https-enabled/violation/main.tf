resource "alicloud_slb_listener" "http" {
  load_balancer_id = "lb-abc123"
  frontend_port    = 80
  backend_port     = 80
  protocol         = "http"
  bandwidth        = 10
}
