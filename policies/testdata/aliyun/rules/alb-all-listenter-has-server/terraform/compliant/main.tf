resource "alicloud_alb_listener" "https" {
  listener_protocol = "HTTPS"
  server_group_id   = "sg-app"
}
