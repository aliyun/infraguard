resource "alicloud_ess_scaling_group" "with_slb" {
  scaling_group_name = "with-slb"
  min_size           = 1
  max_size           = 3
  vswitch_ids        = ["vsw-a", "vsw-b"]
  loadbalancer_ids   = ["lb-123"]
}
