resource "alicloud_oss_bucket" "kms_no_byok" {
  bucket = "my-kms-no-byok-bucket"
  acl    = "private"

  server_side_encryption_rule {
    sse_algorithm = "KMS"
  }
}
