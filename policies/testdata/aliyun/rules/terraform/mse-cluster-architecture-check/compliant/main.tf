resource "alicloud_mse_cluster" "ha_cluster" {
  cluster_specification = "MSE_SC_2_4_60_c"
  cluster_type          = "Nacos-Ans"
  cluster_version       = "NACOS_2_0_0"
  instance_count        = 5
  net_type              = "privatenet"
  vswitch_id            = "vsw-xxx"
  mse_version           = "mse_pro"
}
