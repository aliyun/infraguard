resource "alicloud_slb_acl" "open" {
  name = "my-acl"

  entry_list {
    entry   = "0.0.0.0/0"
    comment = "allow all"
  }
}
