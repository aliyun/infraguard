resource "alicloud_eip_address" "protected" {
  address_name        = "protected"
  deletion_protection = true
}
