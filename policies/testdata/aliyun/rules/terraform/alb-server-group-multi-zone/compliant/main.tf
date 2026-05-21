resource "alicloud_alb_server_group" "app" {
  server_group_id   = "sg-app"
  server_group_type = "Instance"
}

resource "alicloud_instance" "one" {
  instance_name = "one"
  zone_id       = "cn-hangzhou-h"
}

resource "alicloud_instance" "two" {
  instance_name = "two"
  zone_id       = "cn-hangzhou-i"
}

resource "alicloud_alb_server_group_server_attachment" "one" {
  server_group_id = "sg-app"
  server_id       = "one"
}

resource "alicloud_alb_server_group_server_attachment" "two" {
  server_group_id = "sg-app"
  server_id       = "two"
}
