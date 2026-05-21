resource "alicloud_alb_acl" "public" {
  acl_name = "public"

  acl_entries {
    entry       = "0.0.0.0/0"
    description = "all"
  }
}
