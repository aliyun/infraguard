resource "alicloud_ess_scaling_group" "without_slb" {
  scaling_group_name = "without-slb"
  min_size           = 1
  max_size           = 3
  vswitch_ids        = ["vsw-a", "vsw-b"]
}
