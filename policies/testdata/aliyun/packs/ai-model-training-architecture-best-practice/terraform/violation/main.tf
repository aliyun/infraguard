resource "alicloud_ecs_disk" "unencrypted" {
  zone_id              = "cn-hangzhou-i"
  category             = "cloud_essd"
  size                 = 100
  encrypted            = false
  enable_auto_snapshot = false
}
