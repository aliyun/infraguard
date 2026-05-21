resource "alicloud_ess_scaling_configuration" "without_sg" {
  scaling_group_id = "asg-123"
  image_id         = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  instance_type    = "ecs.s6-c1m1.small"
}
