resource "alicloud_oss_bucket" "encrypted_bucket" {
  bucket = "my-encrypted-bucket"
  acl    = "private"

  server_side_encryption_rule {
    sse_algorithm = "AES256"
  }
}
