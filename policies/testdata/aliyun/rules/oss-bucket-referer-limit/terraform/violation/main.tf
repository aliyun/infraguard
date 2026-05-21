resource "alicloud_oss_bucket" "no_referer" {
  bucket = "my-bucket-no-referer"
  acl    = "private"
}
