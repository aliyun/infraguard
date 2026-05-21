resource "alicloud_ecs_disk" "unencrypted" {
  zone_id   = "cn-hangzhou-i"
  category  = "cloud_essd"
  size      = 40
  encrypted = false
}
