resource "alicloud_ecs_disk" "data_disk" {
  zone_id  = "cn-hangzhou-i"
  category = "cloud_regional_disk_auto"
  size     = 40
}
