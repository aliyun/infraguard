resource "alicloud_kms_key" "compliant" {
  description         = "test key"
  key_usage           = "ENCRYPT/DECRYPT"
  deletion_protection = "Enabled"
}
