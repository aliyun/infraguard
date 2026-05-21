resource "alicloud_oss_bucket" "no_logging" {
  bucket = "my-bucket-no-logging"
  acl    = "private"
}
