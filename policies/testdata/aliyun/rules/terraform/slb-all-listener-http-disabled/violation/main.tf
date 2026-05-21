resource "alicloud_slb_listener" "http" {
  load_balancer_id = "lb-123"
  frontend_port    = 80
  protocol         = "http"
}
