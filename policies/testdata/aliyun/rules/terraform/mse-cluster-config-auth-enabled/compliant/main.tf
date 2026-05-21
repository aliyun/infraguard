resource "alicloud_mse_cluster" "example" {
  cluster_specification = "MSE_SC_1_2_60_c"
  cluster_type          = "Nacos-Ans"
  cluster_version       = "NACOS_2_0_0"
  instance_count        = 3
  net_type              = "privatenet"
  mse_version           = "mse_pro"
  vswitch_id            = "vsw-123456"
  acl_entry_list        = ["127.0.0.1/32"]
}
