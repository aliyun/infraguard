resource "alicloud_slb_listener" "http_redirect" {
  load_balancer_id = "lb-123"
  frontend_port    = 80
  protocol         = "http"
  listener_forward = "on"
  forward_port     = 443
}
