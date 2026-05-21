resource "alicloud_kms_instance" "compliant" {
  product_version = "3"
  vpc_id          = "vpc-123456"
  zone_ids        = ["cn-hangzhou-h", "cn-hangzhou-g"]
  vswitch_ids     = ["vsw-123", "vsw-456"]
  vpc_num         = 1
  key_num         = 1000
  secret_num      = 100
  spec            = "1000"
}
