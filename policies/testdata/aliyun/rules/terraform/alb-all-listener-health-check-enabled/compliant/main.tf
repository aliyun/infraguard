resource "alicloud_alb_listener" "https" {
  listener_protocol = "HTTPS"
  server_group_id   = "sg-healthy"
}

resource "alicloud_alb_server_group" "healthy" {
  server_group_id = "sg-healthy"

  health_check_config {
    health_check_enabled = true
  }
}
