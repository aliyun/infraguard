resource "alicloud_oss_bucket" "public_read" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
