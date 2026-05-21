resource "alicloud_ess_scaling_configuration" "encrypted_system" {
  scaling_group_id      = "asg-123"
  image_id              = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  instance_type         = "ecs.s6-c1m1.small"
  security_group_id     = "sg-123"
  system_disk_encrypted = true
}
