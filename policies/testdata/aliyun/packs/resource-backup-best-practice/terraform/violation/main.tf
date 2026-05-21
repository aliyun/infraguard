resource "alicloud_oss_bucket" "no_versioning" {
  bucket = "my-bucket-no-versioning"
  acl    = "private"
}
