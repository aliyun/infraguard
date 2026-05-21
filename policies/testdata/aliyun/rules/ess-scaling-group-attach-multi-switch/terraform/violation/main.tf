resource "alicloud_ess_scaling_group" "single_zone" {
  scaling_group_name = "single-zone"
  min_size           = 1
  max_size           = 3
  vswitch_ids        = ["vsw-a"]
}
