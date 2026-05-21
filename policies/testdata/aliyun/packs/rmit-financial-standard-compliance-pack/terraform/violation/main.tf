resource "alicloud_oss_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read-write"
}
