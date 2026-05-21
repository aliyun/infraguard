resource "alicloud_eip_address" "unprotected" {
  address_name        = "unprotected"
  deletion_protection = false
}
