resource "alicloud_ess_scaling_configuration" "without_image" {
  scaling_group_id  = "asg-123"
  instance_type     = "ecs.s6-c1m1.small"
  security_group_id = "sg-123"
}
