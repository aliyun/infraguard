resource "alicloud_kms_instance" "violation" {
  product_version = "3"
  vpc_id          = "vpc-123456"
  zone_ids        = ["cn-hangzhou-h"]
  vswitch_ids     = ["vsw-123"]
  vpc_num         = 1
  key_num         = 1000
  secret_num      = 100
  spec            = "1000"
}
