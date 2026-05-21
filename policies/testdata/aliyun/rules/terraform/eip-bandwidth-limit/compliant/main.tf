resource "alicloud_eip_address" "limited" {
  address_name = "limited"
  bandwidth    = "50"
}
