resource "alicloud_network_acl" "default" {
  vpc_id           = "vpc-abc123"
  network_acl_name = "my-acl"

  ingress_acl_entries {
    description       = "Allow internal traffic"
    source_cidr_ip    = "10.0.0.0/8"
    port              = "1/65535"
    protocol          = "all"
    policy            = "accept"
  }
}
