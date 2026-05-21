resource "alicloud_ecs_launch_template" "template" {
  launch_template_name = "missing-image-template"
  instance_type        = "ecs.s6-c1m1.small"
}
