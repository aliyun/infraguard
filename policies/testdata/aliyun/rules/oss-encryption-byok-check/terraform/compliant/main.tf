resource "alicloud_oss_bucket" "byok_encrypted" {
  bucket = "my-byok-bucket"
  acl    = "private"

  server_side_encryption_rule {
    sse_algorithm     = "KMS"
    kms_master_key_id = "key-12345678-abcd-1234-abcd-123456789012"
  }
}
