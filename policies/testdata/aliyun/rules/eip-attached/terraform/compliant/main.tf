resource "alicloud_eip_address" "attached" {
  address_name   = "attached"
  allocation_id  = "eip-123456"
  bandwidth      = "5"
}

resource "alicloud_eip_association" "attached" {
  allocation_id = "eip-123456"
  instance_id   = "i-123456"
}
