resource "alicloud_mse_gateway" "example" {
  gateway_name = "my-gateway"
  replica      = 2
  spec         = "MSE_GTW_2_4_200_c"
  vswitch_id   = "vsw-123456"
  vpc_id       = "vpc-123456"
}
