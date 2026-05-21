resource "alicloud_kms_secret" "compliant" {
  secret_name                = "test-secret"
  secret_data                = "secret-value"
  version_id                 = "v1"
  enable_automatic_rotation  = true
  rotation_interval          = "30d"
}
