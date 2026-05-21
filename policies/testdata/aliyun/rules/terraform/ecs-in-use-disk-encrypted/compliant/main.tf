resource "alicloud_ecs_disk" "data_disk" {
  zone_id   = "cn-hangzhou-i"
  category  = "cloud_essd"
  size      = 40
  encrypted = true
}

resource "alicloud_ecs_disk_attachment" "data_disk" {
  disk_id     = "data_disk"
  instance_id = "i-example"
}
