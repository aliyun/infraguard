resource "alicloud_ecs_launch_template" "template" {
  launch_template_name = "encrypted-data-disk-template"
  image_id             = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  instance_type        = "ecs.s6-c1m1.small"

  data_disks {
    category  = "cloud_essd"
    size      = 40
    encrypted = true
  }
}
