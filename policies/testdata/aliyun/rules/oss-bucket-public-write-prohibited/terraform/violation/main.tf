resource "alicloud_oss_bucket" "public_write_bucket" {
  bucket = "my-public-write-bucket"
  acl    = "public-read-write"
}
