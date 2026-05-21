resource "alicloud_oss_bucket" "no_encryption" {
  bucket = "my-bucket-no-encryption"
  acl    = "private"
}
