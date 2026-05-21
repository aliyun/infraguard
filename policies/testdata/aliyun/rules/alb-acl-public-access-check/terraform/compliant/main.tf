resource "alicloud_alb_acl" "restricted" {
  acl_name = "restricted"

  acl_entries {
    entry       = "10.0.0.0/8"
    description = "internal"
  }
}
