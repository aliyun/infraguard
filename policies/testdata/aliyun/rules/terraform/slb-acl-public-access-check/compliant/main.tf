resource "alicloud_slb_acl" "restricted" {
  name = "my-acl"

  entry_list {
    entry   = "10.0.0.0/8"
    comment = "internal network"
  }

  entry_list {
    entry   = "192.168.1.0/24"
    comment = "office network"
  }
}
