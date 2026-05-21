resource "alicloud_network_acl" "default" {
  vpc_id           = "vpc-abc123"
  network_acl_name = "my-acl"

  ingress_acl_entries {
    description       = "Allow SSH from trusted range"
    source_cidr_ip    = "10.0.0.0/8"
    port              = "22/22"
    protocol          = "tcp"
    policy            = "accept"
  }

  ingress_acl_entries {
    description       = "Allow HTTPS from anywhere"
    source_cidr_ip    = "0.0.0.0/0"
    port              = "443/443"
    protocol          = "tcp"
    policy            = "accept"
  }
}
