resource "alicloud_slb_listener" "https" {
  load_balancer_id = "lb-123"
  frontend_port    = 443
  protocol         = "https"
  acl_status       = "on"
  acl_id           = "acl-123"
  acl_type         = "white"
}
