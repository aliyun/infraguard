resource "alicloud_alb_server_group" "app" {
  server_group_id   = "sg-app"
  server_group_type = "Instance"
}

resource "alicloud_alb_server_group_server_attachment" "one" {
  server_group_id = "sg-app"
  server_id       = "i-1"
}

resource "alicloud_alb_server_group_server_attachment" "two" {
  server_group_id = "sg-app"
  server_id       = "i-2"
}
