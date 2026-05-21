resource "alicloud_instance" "web" {
  instance_type       = "ecs.g6.large"
  image_id            = "ubuntu_20_04_x64_20G_alibase_20210623.vhd"
  deletion_protection = false
}
