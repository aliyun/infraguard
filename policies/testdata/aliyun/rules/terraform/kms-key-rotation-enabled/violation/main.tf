resource "alicloud_kms_key" "violation" {
  description        = "test key"
  key_usage          = "ENCRYPT/DECRYPT"
  automatic_rotation = "Disabled"
}
