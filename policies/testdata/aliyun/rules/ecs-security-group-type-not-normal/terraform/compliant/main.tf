resource "alicloud_security_group" "enterprise" {
  name                = "enterprise-sg"
  security_group_type = "enterprise"
}
