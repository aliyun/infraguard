resource "alicloud_oss_bucket" "no_https_policy" {
  bucket = "my-bucket-no-https"
  acl    = "private"
}
