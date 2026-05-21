resource "alicloud_alb_listener" "https" {
  listener_protocol = "HTTPS"
  server_group_id   = "sg-unhealthy"
}

resource "alicloud_alb_server_group" "unhealthy" {
  server_group_id = "sg-unhealthy"

  health_check_config {
    health_check_enabled = false
  }
}
