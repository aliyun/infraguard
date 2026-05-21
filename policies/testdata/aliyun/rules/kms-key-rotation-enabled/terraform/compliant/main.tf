resource "alicloud_kms_key" "compliant" {
  description        = "test key"
  key_usage          = "ENCRYPT/DECRYPT"
  automatic_rotation = "Enabled"
  rotation_interval  = "365d"
}
