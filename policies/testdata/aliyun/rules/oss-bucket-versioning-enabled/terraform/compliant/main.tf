resource "alicloud_oss_bucket" "versioned_bucket" {
  bucket = "my-versioned-bucket"
  acl    = "private"

  versioning {
    status = "Enabled"
  }
}
