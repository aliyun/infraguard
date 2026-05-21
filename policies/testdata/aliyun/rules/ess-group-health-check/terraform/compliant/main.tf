resource "alicloud_ess_scaling_group" "checked" {
  scaling_group_name = "checked"
  min_size           = 1
  max_size           = 3
  vswitch_ids        = ["vsw-a", "vsw-b"]
  health_check_type  = "ECS"
}
