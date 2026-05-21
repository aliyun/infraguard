resource "alicloud_oss_bucket" "kms_encrypted" {
  bucket = "my-kms-bucket"
  acl    = "private"

  server_side_encryption_rule {
    sse_algorithm = "KMS"
  }
}
