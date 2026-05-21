resource "alicloud_mse_gateway" "single_gateway" {
  gateway_name = "my-gateway"
  replica      = 1
  spec         = "MSE_GTW_2_4_200_c"
  vpc_id       = "vpc-xxx"
  vswitch_id   = "vsw-xxx"
}
