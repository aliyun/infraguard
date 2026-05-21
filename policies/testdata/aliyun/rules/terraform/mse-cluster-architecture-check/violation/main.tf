resource "alicloud_mse_cluster" "small_cluster" {
  cluster_specification = "MSE_SC_1_2_60_c"
  cluster_type          = "Nacos-Ans"
  cluster_version       = "NACOS_2_0_0"
  instance_count        = 3
  net_type              = "privatenet"
  vswitch_id            = "vsw-xxx"
  mse_version           = "mse_dev"
}
