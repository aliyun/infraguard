resource "alicloud_vswitch" "too_few_ips" {
  vswitch_name = "my-vswitch"
  vpc_id       = "vpc-abc123"
  cidr_block   = "172.16.0.0/29"
  zone_id      = "cn-hangzhou-b"
}
