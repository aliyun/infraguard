resource "alicloud_kms_key" "violation" {
  description         = "test key"
  key_usage           = "ENCRYPT/DECRYPT"
  deletion_protection = "Disabled"
}
