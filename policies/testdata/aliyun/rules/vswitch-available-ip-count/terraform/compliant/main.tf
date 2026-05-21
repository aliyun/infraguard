resource "alicloud_vswitch" "sufficient_ips" {
  vswitch_name = "my-vswitch"
  vpc_id       = "vpc-abc123"
  cidr_block   = "172.16.0.0/24"
  zone_id      = "cn-hangzhou-b"
}
