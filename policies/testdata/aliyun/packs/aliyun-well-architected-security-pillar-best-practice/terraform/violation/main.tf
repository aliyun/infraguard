resource "alicloud_oss_bucket" "no_logging" {
  bucket = "my-noncompliant-bucket"
  acl    = "private"
}
