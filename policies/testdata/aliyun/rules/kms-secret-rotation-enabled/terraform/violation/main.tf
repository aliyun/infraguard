resource "alicloud_kms_secret" "violation" {
  secret_name                = "test-secret"
  secret_data                = "secret-value"
  version_id                 = "v1"
  enable_automatic_rotation  = false
}
