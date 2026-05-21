resource "alicloud_ess_scaling_group" "unchecked" {
  scaling_group_name = "unchecked"
  min_size           = 1
  max_size           = 3
  vswitch_ids        = ["vsw-a", "vsw-b"]
  health_check_type  = "NONE"
}
