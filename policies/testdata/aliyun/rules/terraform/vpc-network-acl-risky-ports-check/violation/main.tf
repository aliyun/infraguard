resource "alicloud_network_acl" "default" {
  vpc_id           = "vpc-abc123"
  network_acl_name = "my-acl"

  ingress_acl_entries {
    description       = "Allow SSH from anywhere"
    source_cidr_ip    = "0.0.0.0/0"
    port              = "22/22"
    protocol          = "tcp"
    policy            = "accept"
  }

  ingress_acl_entries {
    description       = "Allow RDP from anywhere"
    source_cidr_ip    = "0.0.0.0/0"
    port              = "3389/3389"
    protocol          = "tcp"
    policy            = "accept"
  }
}

resource "alicloud_network_acl" "single_entry" {
  vpc_id           = "vpc-def456"
  network_acl_name = "my-acl-single"

  ingress_acl_entries {
    description       = "Allow SSH from anywhere"
    source_cidr_ip    = "0.0.0.0/0"
    port              = "22/22"
    protocol          = "tcp"
    policy            = "accept"
  }
}
