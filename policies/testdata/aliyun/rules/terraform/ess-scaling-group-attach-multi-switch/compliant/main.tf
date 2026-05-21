resource "alicloud_ess_scaling_group" "multi_zone" {
  scaling_group_name = "multi-zone"
  min_size           = 1
  max_size           = 3
  vswitch_ids        = ["vsw-a", "vsw-b"]
}
