resource "alicloud_network_acl" "default" {
  vpc_id           = "vpc-abc123"
  network_acl_name = "my-acl"
}
