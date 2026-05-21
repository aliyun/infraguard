resource "alicloud_oss_bucket" "logged_bucket" {
  bucket = "my-logged-bucket"
  acl    = "private"

  logging {
    target_bucket = "my-log-bucket"
    target_prefix = "logs/"
  }
}
