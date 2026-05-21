resource "alicloud_mse_gateway" "ha_gateway" {
  gateway_name = "my-gateway"
  replica      = 2
  spec         = "MSE_GTW_2_4_200_c"
  vpc_id       = "vpc-xxx"
  vswitch_id   = "vsw-xxx"
}
