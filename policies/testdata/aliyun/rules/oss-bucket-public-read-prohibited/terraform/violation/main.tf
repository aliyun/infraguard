resource "alicloud_oss_bucket" "public_read_bucket" {
  bucket = "my-public-read-bucket"
  acl    = "public-read"
}
