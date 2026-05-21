resource "alicloud_vpc" "default" {
  vpc_name   = "my-vpc"
  cidr_block = "172.16.0.0/12"
}
