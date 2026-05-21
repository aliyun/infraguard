resource "alicloud_ess_scaling_group" "without_load_balancer" {
  scaling_group_name = "without-load-balancer"
  min_size           = 1
  max_size           = 3
  vswitch_ids        = ["vsw-a", "vsw-b"]
}
