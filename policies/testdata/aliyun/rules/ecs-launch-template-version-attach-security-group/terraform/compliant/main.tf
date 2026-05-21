resource "alicloud_ecs_launch_template" "template" {
  launch_template_name = "secure-template"
  image_id             = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  instance_type        = "ecs.s6-c1m1.small"
  security_group_ids   = ["sg-123456"]
}
