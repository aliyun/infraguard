resource "alicloud_oss_bucket" "aes_encrypted" {
  bucket = "my-aes-bucket"
  acl    = "private"

  server_side_encryption_rule {
    sse_algorithm = "AES256"
  }
}
